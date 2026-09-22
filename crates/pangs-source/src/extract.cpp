// The only Clang-owned objects live in this translation unit. Each AST is
// released after its facts have been copied into the JSON result. The Rust
// planner never stores cursors or adds source edges to LLVM's runtime graph.
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/Attr.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecordLayout.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/TypeLoc.h>
#include <clang/Basic/Version.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>
#include <clang/Driver/Driver.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Job.h>
#include <clang/Index/USRGeneration.h>
#include <clang/Lex/Lexer.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/Host.h>
#include <llvm/Support/raw_ostream.h>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::tooling;
using llvm::json::Array;
using llvm::json::Object;
using llvm::json::Value;

namespace {
struct Node {
  std::string function;
  std::set<std::string> blockers;
  Array edits;
};
struct ConditionalChange {
  std::set<std::string> dependencies;
  std::set<std::string> blockers;
  Array edits;
};
struct Facts {
  std::map<std::string, Node> nodes;
  std::map<std::string, ConditionalChange> conditional_changes;
  std::map<std::string, Object> producers;
  Array wrappers;
  Array edges, calls, uses, functions, records, variables, invocations, pruned_declarations;
  Array unprunable_declarations;
  std::set<std::string> globals, identifiers, no_initializer, initialized;
  std::map<std::string, std::set<std::string>> clone_users;
};

// Match C2Rust's TypedAstContext::prune_unwanted_items(false), per TU.
// This is declaration dependency closure, NOT executable/LLVM reachability:
// references in if(0), sizeof, initializers and cleanup attributes still count.
class Retention : public RecursiveASTVisitor<Retention> {
  std::set<const Decl *> retained;
  std::vector<Decl *> pending;
  std::set<const Decl *> visited;
  std::set<const Stmt *> folded_operands;
public:
  bool TraverseStmt(Stmt *s) {
    return !s || folded_operands.count(s) || RecursiveASTVisitor::TraverseStmt(s);
  }
  void keep(const Decl *d) {
    if (!d || !retained.insert(d->getCanonicalDecl()).second) return;
    if (auto *f = dyn_cast<FunctionDecl>(d)) {
      for (auto *r : f->redecls()) pending.push_back(r);
    } else if (auto *v = dyn_cast<VarDecl>(d)) {
      for (auto *r : v->redecls()) pending.push_back(r);
    } else if (auto *t = dyn_cast<TagDecl>(d)) {
      for (auto *r : t->redecls()) pending.push_back(r);
    } else pending.push_back(const_cast<Decl *>(d));
  }
  bool contains(const Decl *d) const {
    return retained.count(d->getCanonicalDecl());
  }
  bool VisitDecl(Decl *d) { keep(d); return true; }
  bool VisitDeclRefExpr(DeclRefExpr *e) {
    keep(e->getDecl());
    if (isa<EnumConstantDecl>(e->getDecl()))
      keep(cast<Decl>(e->getDecl()->getDeclContext()));
    return true;
  }
  bool VisitMemberExpr(MemberExpr *e) { keep(e->getMemberDecl()); return true; }
  bool VisitTagType(TagType *t) { keep(t->getDecl()); return true; }
  bool VisitTypedefType(TypedefType *t) { keep(t->getDecl()); return true; }
  bool VisitVarDecl(VarDecl *v) {
    if (auto *cleanup = v->getAttr<CleanupAttr>()) keep(cleanup->getFunctionDecl());
    return true;
  }
  bool VisitEnumConstantDecl(EnumConstantDecl *d) {
    folded_operands.insert(d->getInitExpr()); return true;
  }
  bool VisitFieldDecl(FieldDecl *d) {
    if (d->isBitField()) folded_operands.insert(d->getBitWidth());
    return true;
  }
  bool TraverseAlignedAttr(AlignedAttr *) { return true; }
  bool TraverseTypeTraitExpr(TypeTraitExpr *) { return true; }
  bool TraverseGenericSelectionExpr(GenericSelectionExpr *e) {
    // AstExporter::VisitGenericSelectionExpr exports only this expression:
    // neither the controlling operand nor the unselected associations are
    // dependencies of C2Rust's typed AST.
    return TraverseStmt(e->getResultExpr());
  }
  bool TraverseTypeOfExprType(TypeOfExprType *t) { return TraverseType(t->desugar()); }
  bool TraverseTypeOfExprTypeLoc(TypeOfExprTypeLoc loc) {
    return TraverseType(loc.getTypePtr()->desugar());
  }
  bool TraverseConstantArrayType(ConstantArrayType *t) {
    return TraverseType(t->getElementType());
  }
  bool TraverseConstantArrayTypeLoc(ConstantArrayTypeLoc loc) {
    // The exporter retains the element type and evaluated bound, not the
    // source bound's sizeof/type/enum dependencies. VLAs are different.
    return TraverseTypeLoc(loc.getElementLoc());
  }
  explicit Retention(ASTContext &ctx) {
    for (auto *d : ctx.getTranslationUnitDecl()->decls()) {
      if (auto *f = dyn_cast<FunctionDecl>(d)) {
        auto *def = f->getDefinition();
        if ((def && f->isGlobal() &&
             (!def->isInlineSpecified() || def->isInlineDefinitionExternallyVisible())) ||
            f->hasAttr<UsedAttr>()) keep(f);
      } else if (auto *v = dyn_cast<VarDecl>(d)) {
        if ((v->isThisDeclarationADefinition() && v->isExternallyVisible()) ||
            v->hasAttr<UsedAttr>()) keep(v);
      }
    }
    while (!pending.empty()) {
      auto *d = pending.back(); pending.pop_back();
      if (visited.insert(d).second) TraverseDecl(d);
    }
  }
};

// Identify discarded declarations whose syntax could become invalid when a
// referenced function or global is rewritten. The dependency graph decides
// per localization recipe whether their physical removal is actually needed.
class PhysicalPruning : public RecursiveASTVisitor<PhysicalPruning> {
  std::set<const Decl *> visited;
public:
  bool required = false;
  bool TraverseDecl(Decl *d) {
    return !d || !visited.insert(d).second || RecursiveASTVisitor::TraverseDecl(d);
  }
  bool VisitFunctionDecl(FunctionDecl *d) {
    required |= d->doesThisDeclarationHaveABody(); return true;
  }
  bool VisitVarDecl(VarDecl *d) {
    required |= d->hasGlobalStorage() && d->isThisDeclarationADefinition();
    required |= d->hasAttr<CleanupAttr>();
    return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *) { required = true; return true; }
  bool VisitTypedefType(TypedefType *t) { return TraverseDecl(t->getDecl()); }
  bool VisitTagType(TagType *t) {
    auto *d = t->getDecl();
    return TraverseDecl(d->getDefinition() ? d->getDefinition() : d);
  }
};

class DependencyCollector : public RecursiveASTVisitor<DependencyCollector> {
  void observe(const Decl *d) {
    if (d) declarations.insert(d->getCanonicalDecl());
  }
public:
  std::set<const Decl *> declarations;
  bool VisitDeclRefExpr(DeclRefExpr *e) {
    observe(e->getDecl());
    if (auto *constant = dyn_cast<EnumConstantDecl>(e->getDecl()))
      observe(dyn_cast<Decl>(constant->getDeclContext()));
    return true;
  }
  bool VisitMemberExpr(MemberExpr *e) { observe(e->getMemberDecl()); return true; }
  bool VisitTagType(TagType *t) { observe(t->getDecl()); return true; }
  bool VisitTypedefType(TypedefType *t) { observe(t->getDecl()); return true; }
};

class Extract : public RecursiveASTVisitor<Extract> {
  ASTContext &ctx;
  SourceManager &sm;
  Facts &out;
  const Retention &retention;
  std::string function, initializer;
  std::set<const Decl *> typed;
  std::map<const Decl *, std::string> pruning_nodes;
  std::set<const FunctionDecl *> wrapper_declarations;
  unsigned unknown_count = 0;
  std::set<const Stmt *> folded_operands;

  std::string file(SourceLocation loc) {
    return sm.getFilename(sm.getSpellingLoc(loc)).str();
  }
  unsigned offset(SourceLocation loc) {
    return sm.getFileOffset(sm.getSpellingLoc(loc));
  }
  std::string text(SourceLocation begin, SourceLocation end) {
    return Lexer::getSourceText(CharSourceRange::getCharRange(begin, end), sm,
                               ctx.getLangOpts()).str();
  }
  bool editable(SourceLocation loc) {
    return loc.isValid() && !loc.isMacroID() && sm.isWrittenInMainFile(loc);
  }
  Object edit(SourceLocation begin, SourceLocation end, std::string replacement,
              const std::string &kind) {
    return Object{{"file", file(begin)}, {"start", offset(begin)},
                  {"end", offset(end)},
                  {"replacement", std::move(replacement)}, {"kind", kind}};
  }
  std::string recordId(const RecordDecl *r) {
    // Clang's USR for sibling anonymous unions can be identical (@Ua).
    // Their containing field position, unlike a source filename, is shared
    // across the preprocessed copies of a header in different TUs.
    if (!r->getIdentifier() && !r->getTypedefNameForAnonDecl()) {
      if (auto *parent = dyn_cast<RecordDecl>(r->getDeclContext())) {
        unsigned i = 0;
        for (auto *field : parent->fields()) {
          QualType t = field->getType();
          while (true) {
            if (t->isPointerType()) t = t->getPointeeType();
            else if (auto *a = ctx.getAsArrayType(t)) t = a->getElementType();
            else break;
          }
          if (auto *type = t->getAs<RecordType>())
            if (type->getDecl()->getCanonicalDecl() == r->getCanonicalDecl())
              return recordId(parent) + ":anonymous-field:" + std::to_string(i);
          ++i;
        }
      }
    }
    llvm::SmallString<128> usr;
    if (!index::generateUSRForDecl(r, usr)) return usr.str().str();
    return "record:" + file(r->getLocation()) + ":" + std::to_string(offset(r->getLocation()));
  }
  std::string typeSignature(QualType t) {
    auto policy = ctx.getPrintingPolicy();
    // Layouts and nested fields are checked separately using recordId().
    // Source paths printed in anonymous tag names are not type differences.
    policy.AnonymousTagLocations = false;
    std::string identities;
    collectTypeRecords(t, identities);
    return identities + t.getCanonicalType().getAsString(policy);
  }
  void collectTypeRecords(QualType t, std::string &result) {
    t = t.getCanonicalType();
    if (auto *r = t->getAs<RecordType>()) result += "[record:" + recordId(r->getDecl()) + "]";
    else if (t->isPointerType()) collectTypeRecords(t->getPointeeType(), result);
    else if (auto *a = ctx.getAsArrayType(t)) collectTypeRecords(a->getElementType(), result);
    else if (auto *f = t->getAs<FunctionType>()) {
      collectTypeRecords(f->getReturnType(), result);
      if (auto *p = dyn_cast<FunctionProtoType>(f))
        for (auto parameter : p->param_types()) collectTypeRecords(parameter, result);
    }
  }
  std::string id(const ValueDecl *d) {
    if (auto *field = dyn_cast<FieldDecl>(d))
      return recordId(field->getParent()) + ":field:" + std::to_string(field->getFieldIndex());
    if (auto *f = dyn_cast<FunctionDecl>(d)) {
      auto key = "fn:" + f->getNameAsString();
      out.nodes[key].function = f->getNameAsString();
      return key;
    }
    if (auto *p = dyn_cast<ParmVarDecl>(d)) {
      if (auto *f = dyn_cast<FunctionDecl>(p->getDeclContext())) {
        for (unsigned i = 0; i < f->getNumParams(); ++i)
          if (f->getParamDecl(i) == p)
            return "param:" + f->getNameAsString() + ":" + std::to_string(i);
      }
    }
    llvm::SmallString<128> usr;
    if (index::generateUSRForDecl(d, usr)) {
      return "decl:" + file(d->getLocation()) + ":" +
             std::to_string(offset(d->getLocation()));
    }
    return usr.str().str();
  }
  bool callable(QualType t) {
    if (t.isNull()) return false;
    t = t.getCanonicalType();
    if (t->isFunctionType()) return true;
    if (auto *a = ctx.getAsArrayType(t)) return callable(a->getElementType());
    return t->isPointerType() && callable(t->getPointeeType());
  }
  std::string unknown(const Expr *e, const std::string &why) {
    auto key = "unknown:" + file(e->getBeginLoc()) + ":" +
               std::to_string(offset(e->getBeginLoc())) + ":" +
               std::to_string(unknown_count++);
    out.nodes[key].blockers.insert(why);
    // Unknown is not empty: retain every syntactic producer/slot below it.
    std::vector<std::string> references;
    collectReferences(e, references);
    connect({key}, references);
    return key;
  }
  void collectReferences(const Stmt *s, std::vector<std::string> &result) {
    if (!s) return;
    if (auto *g = dyn_cast<GenericSelectionExpr>(s)) {
      collectReferences(g->getResultExpr(), result); return;
    }
    if (auto *d = dyn_cast<DeclRefExpr>(s)) {
      if (callable(d->getType())) {
        auto refs = values(d);
        result.insert(result.end(), refs.begin(), refs.end());
      }
    } else if (auto *m = dyn_cast<MemberExpr>(s)) {
      if (callable(m->getType())) result.push_back(id(m->getMemberDecl()));
    }
    for (auto *child : s->children()) collectReferences(child, result);
  }
  void connect(const std::vector<std::string> &a, const std::vector<std::string> &b) {
    for (const auto &x : a) for (const auto &y : b) {
      out.nodes[x]; out.nodes[y];
      if (x != y) out.edges.push_back(Array{x, y});
    }
  }
  // Flow is between declaration/storage identities, never compatible types.
  std::vector<std::string> values(const Expr *e) {
    if (!e) return {};
    e = e->IgnoreParenImpCasts();
    if (auto *g = dyn_cast<GenericSelectionExpr>(e)) return values(g->getResultExpr());
    if (auto *d = dyn_cast<DeclRefExpr>(e)) {
      if (auto *f = dyn_cast<FunctionDecl>(d->getDecl())) {
        auto begin = d->getLocation();
        auto end = Lexer::getLocForEndOfToken(begin, 0, sm, ctx.getLangOpts());
        auto key = "producer:" + file(begin) + ":" + std::to_string(offset(begin));
        out.nodes[key];
        if (f->getName() == "main")
          out.nodes[key].blockers.insert("source-call-to-main");
        if (!editable(begin) || !editable(end))
          out.nodes[key].blockers.insert("source-uneditable-function-value");
        out.producers.emplace(key, Object{{"function", f->getNameAsString()},
          {"edit", edit(begin, end, f->getNameAsString() + "_xjw", "wrapper-use")}});
        id(f);
        return {key};
      }
      if (callable(d->getType())) return {id(d->getDecl())};
    }
    if (auto *m = dyn_cast<MemberExpr>(e)) {
      if (callable(m->getType())) return {id(m->getMemberDecl())};
    }
    if (auto *s = dyn_cast<ArraySubscriptExpr>(e)) return values(s->getBase());
    if (auto *c = dyn_cast<ConditionalOperator>(e)) {
      auto a = values(c->getTrueExpr()), b = values(c->getFalseExpr());
      a.insert(a.end(), b.begin(), b.end()); return a;
    }
    if (auto *u = dyn_cast<UnaryOperator>(e)) {
      if (u->getOpcode() == UO_AddrOf || u->getOpcode() == UO_Deref) {
        auto a = values(u->getSubExpr());
        if (u->getOpcode() == UO_Deref && u->getSubExpr()->getType()->isPointerType() &&
            u->getSubExpr()->getType()->getPointeeType()->isPointerType())
          for (auto &n : a) out.nodes[n].blockers.insert("source-pointer-indirection");
        return a;
      }
    }
    if (auto *c = dyn_cast<ExplicitCastExpr>(e)) {
      auto a = values(c->getSubExpr());
      if (a.empty() && !callable(c->getType())) return {};
      auto n = unknown(e, "source-callable-cast");
      connect(a, {n}); return {n};
    }
    if (auto *c = dyn_cast<CallExpr>(e)) {
      if (callable(c->getType())) {
        if (auto *f = c->getDirectCallee()) return {"return:" + f->getNameAsString()};
      }
    }
    if (auto *b = dyn_cast<BinaryOperator>(e)) {
      if (b->getOpcode() == BO_Comma || b->isAssignmentOp()) return values(b->getRHS());
    }
    if (e->isNullPointerConstant(ctx, Expr::NPC_ValueDependentIsNotNull)) return {};
    if (callable(e->getType())) return {unknown(e, "source-unmodeled-callable-expression")};
    return {};
  }
  std::vector<std::string> aggregate(QualType t, std::set<const Type *> *seen = nullptr) {
    std::set<const Type *> local;
    if (!seen) seen = &local;
    t = t.getCanonicalType();
    if (!seen->insert(t.getTypePtr()).second) return {};
    if (t->isPointerType()) return aggregate(t->getPointeeType(), seen);
    if (auto *a = ctx.getAsArrayType(t)) return aggregate(a->getElementType(), seen);
    std::vector<std::string> result;
    if (auto *r = t->getAs<RecordType>()) if (auto *def = r->getDecl()->getDefinition()) {
      for (auto *f : def->fields()) {
        if (callable(f->getType())) result.push_back(id(f));
        else {
          auto sub = aggregate(f->getType(), seen);
          result.insert(result.end(), sub.begin(), sub.end());
        }
      }
    }
    return result;
  }
  void blockAggregate(QualType t, const std::string &reason) {
    for (auto &n : aggregate(t)) out.nodes[n].blockers.insert(reason);
  }
  void blockOpaqueOperands(const Stmt *s, const std::string &reason) {
    if (!s) return;
    if (auto *g = dyn_cast<GenericSelectionExpr>(s)) {
      blockOpaqueOperands(g->getResultExpr(), reason); return;
    }
    if (auto *e = dyn_cast<Expr>(s)) {
      for (auto &n : values(e)) out.nodes[n].blockers.insert(reason);
      blockAggregate(e->getType(), reason);
    }
    for (auto *child : s->children()) blockOpaqueOperands(child, reason);
  }
  Object site(SourceLocation loc) {
    return Object{{"file", file(loc)}, {"line", sm.getSpellingLineNumber(loc)},
                  {"col", sm.getSpellingColumnNumber(loc)}, {"offset", offset(loc)},
                  {"function", function}};
  }
  Array observations(const Expr *e) {
    Array result;
    auto record = [&](const char *kind, const Expr *at) {
      result.push_back(Object{{"kind", kind}, {"site", site(at->getBeginLoc())}});
    };
    // sizeof/alignof operands survive declaration pruning but are not emitted
    // as evaluations. Do not turn sizeof(++g) into a storage obligation.
    auto ancestor = DynTypedNode::create(*e);
    for (unsigned depth = 0; depth < 128; ++depth) {
      auto parents = ctx.getParents(ancestor);
      if (parents.size() != 1) break;
      if (auto *trait = parents[0].get<UnaryExprOrTypeTraitExpr>()) {
        // A sizeof VLA can evaluate its bound. In particular, a retained
        // sizeof(int[++g]) still emits an update even inside if(0).
        if (trait->getKind() != UETT_SizeOf || !trait->getTypeOfArgument()->isVariablyModifiedType()) {
          record("unevaluated", e); return result;
        }
      }
      ancestor = parents[0];
    }
    bool decayed = false;
    for (unsigned depth = 0; depth < 64; ++depth) {
      auto parents = ctx.getParents(*e);
      if (parents.size() != 1) break;
      if (auto *cast = parents[0].get<ImplicitCastExpr>()) {
        if (cast->getCastKind() == CK_LValueToRValue) {
          record(e->getType()->isPointerType() ? "pointer-read" : "read", e);
          return result;
        }
        if (cast->getCastKind() == CK_ArrayToPointerDecay) {
          record("array-decay", e); decayed = true;
        } else if (cast->getCastKind() != CK_NoOp) break;
        e = cast;
      } else if (auto *paren = parents[0].get<ParenExpr>()) e = paren;
      else if (auto *generic = parents[0].get<GenericSelectionExpr>()) {
        if (generic->getResultExpr() != e) break;
        e = generic;
      }
      else if (auto *member = parents[0].get<MemberExpr>()) {
        if (member->isArrow()) break;
        e = member;
      } else if (auto *subscript = parents[0].get<ArraySubscriptExpr>()) {
        if (subscript->getBase() != e) break;
        e = subscript; decayed = false;
      }
      else if (auto *unary = parents[0].get<UnaryOperator>()) {
        if (unary->getOpcode() == UO_AddrOf) { record("address", unary); return result; }
        if (unary->isIncrementDecrementOp()) { record("update", unary); return result; }
        // Dereferencing a decayed array is a pointer operation, not a direct
        // Rust static lvalue (C2Rust lowers it through the const raw address).
        break;
      } else if (auto *binary = parents[0].get<BinaryOperator>()) {
        if (binary->isAssignmentOp() && binary->getLHS() == e) {
          record("assignment", binary); return result;
        }
        break;
      } else break;
    }
    if (!decayed) record("unclassified-use", e);
    return result;
  }
  bool containsObjectPointer(QualType t, std::set<const Type *> *seen = nullptr) {
    std::set<const Type *> local;
    if (!seen) seen = &local;
    t = t.getCanonicalType();
    if (!seen->insert(t.getTypePtr()).second) return false;
    if (t->isPointerType()) return !t->getPointeeType()->isFunctionType();
    if (t->isVariableArrayType() || t->isReferenceType() || t->isBlockPointerType()) return true;
    if (auto *a = ctx.getAsArrayType(t)) return containsObjectPointer(a->getElementType(), seen);
    if (auto *a = t->getAs<AtomicType>()) return containsObjectPointer(a->getValueType(), seen);
    if (auto *v = t->getAs<VectorType>()) return containsObjectPointer(v->getElementType(), seen);
    if (auto *r = t->getAs<RecordType>()) if (auto *def = r->getDecl()->getDefinition())
      for (auto *f : def->fields()) if (containsObjectPointer(f->getType(), seen)) return true;
    return false;
  }
  void initializerFunctions(const Stmt *s, Array &functions) {
    if (!s) return;
    if (auto *g = dyn_cast<GenericSelectionExpr>(s)) {
      initializerFunctions(g->getResultExpr(), functions); return;
    }
    if (auto *ref = dyn_cast<DeclRefExpr>(s))
      if (auto *f = dyn_cast<FunctionDecl>(ref->getDecl()))
        functions.push_back(Object{{"name", f->getNameAsString()},
            {"internal", !f->isExternallyVisible()}, {"site", site(ref->getLocation())}});
    for (auto *child : s->children()) initializerFunctions(child, functions);
  }
  void initializerFeatures(const Stmt *s, std::set<std::string> &features) {
    if (!s) return;
    if (auto *g = dyn_cast<GenericSelectionExpr>(s)) {
      initializerFeatures(g->getResultExpr(), features); return;
    }
    if (isa<TypeTraitExpr>(s)) return;
    // Corresponds to C2Rust static_initializer_is_uncompilable. Keep the
    // concrete syntax, not the conclusion that storage must be mutable.
    if (isa<UnaryExprOrTypeTraitExpr>(s)) return;
    if (isa<ArraySubscriptExpr>(s)) features.insert("array-subscript");
    if (isa<MemberExpr>(s)) features.insert("member-access");
    if (isa<AbstractConditionalOperator>(s)) features.insert("conditional");
    if (auto *u = dyn_cast<UnaryOperator>(s))
      if (u->getOpcode() == UO_Minus && u->getType()->isUnsignedIntegerType())
        features.insert("unsigned-negation");
    if (auto *c = dyn_cast<CastExpr>(s)) {
      if (c->getCastKind() == CK_PointerToIntegral) features.insert("pointer-to-integer");
      if (c->getCastKind() == CK_IntegralToPointer && c->getType()->isFunctionPointerType())
        features.insert("integer-to-function-pointer");
    }
    if (auto *b = dyn_cast<BinaryOperator>(s)) {
      if ((b->isAdditiveOp() || b->isMultiplicativeOp()) &&
          (b->getType()->isPointerType() || (b->getType()->isUnsignedIntegerType() &&
           !(isa<UnaryExprOrTypeTraitExpr>(b->getLHS()->IgnoreParens()) &&
             isa<UnaryExprOrTypeTraitExpr>(b->getRHS()->IgnoreParens())))))
        features.insert("pointer-or-unsigned-arithmetic");
    }
    if (auto *init = dyn_cast<InitListExpr>(s))
      if (auto *r = init->getType()->getAs<RecordType>())
        if (auto *def = r->getDecl()->getDefinition(); def && def->isStruct())
          for (auto *f : def->fields()) if (f->isBitField()) features.insert("bitfield-initializer");
    for (auto *child : s->children()) initializerFeatures(child, features);
  }
  // Parameter list locations come from TypeLoc, including nested declarators.
  void typeEdits(const std::string &node, TypeLoc loc, bool named) {
    for (; !loc.isNull(); loc = loc.getNextTypeLoc()) {
      if (auto fn = loc.getAs<FunctionTypeLoc>()) {
        auto *proto = fn.getType()->getAs<FunctionProtoType>();
        if (!proto || proto->isVariadic()) {
          out.nodes[node].blockers.insert("source-nonprototype-or-variadic"); return;
        }
        for (auto t : proto->param_types()) if (!named && callable(t))
          out.nodes[node].blockers.insert("source-nested-callable-type");
        if (!named && callable(proto->getReturnType()))
          out.nodes[node].blockers.insert("source-nested-callable-type");
        auto left = fn.getLParenLoc(), right = fn.getRParenLoc();
        if (!editable(left) || !editable(right)) {
          out.nodes[node].blockers.insert("source-uneditable-declaration"); return;
        }
        // Replacing the opening paren leaves the first parameter's spelling
        // free for a separate typedef-use edit at the following byte offset.
        // With no parameters, replace the whitespace and optional `void`.
        auto begin = fn.getNumParams() ? left : left.getLocWithOffset(1);
        auto end = fn.getNumParams() ? left.getLocWithOffset(1) : right;
        std::string arg = named ? "struct XjGlobals *xjg" : "struct XjGlobals *";
        if (fn.getNumParams()) arg = "(" + arg + ", ";
        out.nodes[node].edits.push_back(edit(begin, end, arg, "signature"));
        return;
      }
      if (auto alias = loc.getAs<TypedefTypeLoc>()) {
        auto *decl = alias.getTypedefNameDecl();
        auto underlying = decl->getTypeSourceInfo()->getTypeLoc();
        for (auto l = underlying; !l.isNull(); l = l.getNextTypeLoc()) {
          if (l.getAs<TypedefTypeLoc>()) {
            out.nodes[node].blockers.insert("source-typedef-alias-chain"); return;
          }
        }
        auto semi = Lexer::findNextToken(decl->getEndLoc(), sm, ctx.getLangOpts());
        if (!semi || !semi->is(tok::semi) || !editable(decl->getBeginLoc()) || !editable(alias.getNameLoc())) {
          out.nodes[node].blockers.insert("source-uneditable-typedef"); return;
        }
        const std::string temp = "temporary-typedef:" + node;
        typeEdits(temp, underlying, false);
        auto edits = std::move(out.nodes[temp].edits);
        auto blockers = std::move(out.nodes[temp].blockers);
        out.nodes.erase(temp);
        out.nodes[node].blockers.insert(blockers.begin(), blockers.end());
        if (!blockers.empty() || edits.size() != 1) return;
        auto clone_name = decl->getNameAsString() + "__pangs_context";
        out.clone_users[clone_name].insert(node);
        auto begin = decl->getBeginLoc();
        auto end = semi->getLocation().getLocWithOffset(1);
        auto clone = text(begin, end);
        auto edit_value = edits[0].getAsObject();
        auto start_offset = *edit_value->getInteger("start");
        auto end_offset = *edit_value->getInteger("end");
        // In a typedef declarator its name precedes the function parameter list.
        if (offset(decl->getLocation()) >= start_offset) {
          out.nodes[node].blockers.insert("source-unmodeled-typedef-declarator"); return;
        }
        clone.replace(start_offset - offset(begin), end_offset - start_offset,
                      edit_value->getString("replacement")->str());
        clone.replace(offset(decl->getLocation()) - offset(begin), decl->getName().size(), clone_name);
        out.nodes[node].edits.push_back(edit(end, end, "\n" + clone + "\n", "typedef-clone"));
        auto use = alias.getNameLoc();
        auto use_end = Lexer::getLocForEndOfToken(use, 0, sm, ctx.getLangOpts());
        out.nodes[node].edits.push_back(edit(use, use_end, clone_name, "typedef-use"));
        return;
      }
    }
    out.nodes[node].blockers.insert("source-missing-callable-typeloc");
  }
  void init(const std::string &node, QualType t, const Expr *e) {
    if (!e) return;
    e = e->IgnoreParenImpCasts();
    if (auto *compound = dyn_cast<CompoundLiteralExpr>(e)) {
      init(node, t, compound->getInitializer());
      return;
    }
    if (auto *list = dyn_cast<InitListExpr>(e)) {
      if (auto *semantic = list->getSemanticForm()) list = semantic;
      if (auto *a = ctx.getAsArrayType(t)) {
        for (auto *v : list->inits()) init(node, a->getElementType(), v);
      } else if (auto *r = t->getAs<RecordType>()) {
        if (r->getDecl()->isUnion()) {
          auto *field = list->getInitializedFieldInUnion();
          if (field && list->getNumInits()) init(id(field), field->getType(), list->getInit(0));
          return;
        }
        unsigned i = 0;
        for (auto *f : r->getDecl()->fields()) {
          if (i == list->getNumInits()) break;
          init(id(f), f->getType(), list->getInit(i++));
        }
      } else for (auto *v : list->inits()) init(node, t, v);
    } else if (callable(t)) connect({node}, values(e));
    else if (t->isRecordType()) blockAggregate(t, "source-aggregate-copy");
    else for (auto &n : values(e)) out.nodes[n].blockers.insert("source-opaque-callable-storage");
  }

public:
  Extract(ASTContext &ctx, Facts &out, const Retention &retention)
      : ctx(ctx), sm(ctx.getSourceManager()), out(out), retention(retention) {}
  bool TraverseStmt(Stmt *s) {
    return !s || folded_operands.count(s) || RecursiveASTVisitor::TraverseStmt(s);
  }
  std::set<std::string> dependencyNodes(const std::set<const Decl *> &declarations) {
    std::set<std::string> result;
    for (auto *d : declarations) {
      if (auto found = pruning_nodes.find(d); found != pruning_nodes.end()) {
        result.insert(found->second);
      } else if (auto *f = dyn_cast<FunctionDecl>(d)) {
        result.insert("fn:" + f->getNameAsString());
      } else if (auto *v = dyn_cast<VarDecl>(d); v && v->hasGlobalStorage()) {
        result.insert("global:" + v->getNameAsString());
      } else if (auto *v = dyn_cast<ValueDecl>(d); v && callable(v->getType())) {
        result.insert(id(v));
      }
    }
    return result;
  }
  std::set<std::string> dependencies(Stmt *s) {
    DependencyCollector collector;
    collector.TraverseStmt(s);
    return dependencyNodes(collector.declarations);
  }
  std::set<std::string> dependencies(TypeLoc loc) {
    DependencyCollector collector;
    collector.TraverseTypeLoc(loc);
    return dependencyNodes(collector.declarations);
  }
  void foldExpression(SourceRange range, const std::string &value,
                      const std::set<std::string> &dependencies) {
    if (dependencies.empty()) return;
    auto begin = range.getBegin();
    auto end = Lexer::getLocForEndOfToken(range.getEnd(), 0, sm, ctx.getLangOpts());
    auto node = "prune-expression:" + file(begin) + ":" + std::to_string(offset(begin));
    out.conditional_changes[node].dependencies.insert(dependencies.begin(), dependencies.end());
    if (editable(begin) && editable(end)) {
      out.conditional_changes[node].edits.push_back(edit(begin, end, value, "prune-expression"));
    } else {
      out.conditional_changes[node].blockers.insert("source-uneditable-folded-expression");
      out.unprunable_declarations.push_back(Object{{"kind", "uneditable-folded-expression"},
          {"site", site(begin)}});
    }
  }
  void foldExpression(Expr *e, const std::string &value) {
    if (!e) return;
    folded_operands.insert(e);
    if (!isa<IntegerLiteral>(e->IgnoreParenImpCasts()))
      foldExpression(e->getSourceRange(), value, dependencies(e));
  }
  bool VisitEnumConstantDecl(EnumConstantDecl *d) {
    llvm::SmallString<32> value;
    d->getInitVal().toString(value, 10);
    foldExpression(d->getInitExpr(), value.str().str() + (d->getInitVal().isSigned() ? "LL" : "ULL"));
    return true;
  }
  bool VisitFieldDecl(FieldDecl *d) {
    if (d->isBitField()) foldExpression(d->getBitWidth(), std::to_string(d->getBitWidthValue(ctx)));
    return true;
  }
  bool TraverseAlignedAttr(AlignedAttr *a) {
    auto value = std::to_string(a->getAlignment(ctx) / ctx.getCharWidth());
    if (a->isAlignmentExpr()) foldExpression(a->getAlignmentExpr(), value);
    else if (auto *t = a->getAlignmentType()) {
      auto loc = t->getTypeLoc();
      foldExpression(loc.getSourceRange(), value, dependencies(loc));
    }
    return true;
  }
  bool TraverseTypeTraitExpr(TypeTraitExpr *e) {
    foldExpression(e, e->getValue() ? "1" : "0"); return true;
  }
  bool TraverseDecl(Decl *d) {
    if (!d) return true;
    // Names remain reserved in the unmodified C snapshot, even when C2Rust
    // would omit their declarations. Extraction itself never changes source.
    if (auto *n = dyn_cast<NamedDecl>(d)) out.identifiers.insert(n->getNameAsString());
    if (!isa<TranslationUnitDecl>(d) && !retention.contains(d)) return true;
    return RecursiveASTVisitor::TraverseDecl(d);
  }
  bool TraverseGenericSelectionExpr(GenericSelectionExpr *e) {
    auto *selected = e->getResultExpr();
    auto required_by = dependencies(e);
    if (required_by.empty()) return TraverseStmt(selected);
    auto begin = e->getBeginLoc(), selected_begin = selected->getBeginLoc();
    auto selected_end = Lexer::getLocForEndOfToken(selected->getEndLoc(), 0, sm, ctx.getLangOpts());
    auto end = Lexer::getLocForEndOfToken(e->getEndLoc(), 0, sm, ctx.getLangOpts());
    auto node = "prune-expression:" + file(begin) + ":" + std::to_string(offset(begin));
    out.conditional_changes[node].dependencies.insert(required_by.begin(), required_by.end());
    if (editable(begin) && editable(selected_begin) && editable(selected_end) && editable(end)) {
      // Pruned declarations may still be named in the controlling operand or
      // discarded alternatives. Remove those spellings before C validation,
      // leaving the selected expression's offsets available for nested edits.
      out.conditional_changes[node].edits.push_back(edit(begin, selected_begin, "(", "prune-expression"));
      out.conditional_changes[node].edits.push_back(edit(selected_end, end, ")", "prune-expression"));
    } else {
      out.conditional_changes[node].blockers.insert("source-uneditable-generic-selection");
      out.unprunable_declarations.push_back(Object{{"kind", "uneditable-generic-selection"},
          {"site", site(begin)}});
    }
    return TraverseStmt(selected);
  }
  bool printableType(QualType t) {
    if (t->getAs<TypedefType>()) return true;
    if (t->isBuiltinType()) return true;
    if (auto *tag = t->getAs<TagType>())
      return tag->getDecl()->getIdentifier() || tag->getDecl()->getTypedefNameForAnonDecl();
    if (t->isPointerType()) return printableType(t->getPointeeType());
    if (auto *a = ctx.getAsArrayType(t)) return !t->isVariableArrayType() && printableType(a->getElementType());
    if (auto *a = t->getAs<AtomicType>()) return printableType(a->getValueType());
    return false;
  }
  bool TraverseTypeOfExprType(TypeOfExprType *t) { return TraverseType(t->desugar()); }
  bool TraverseTypeOfExprTypeLoc(TypeOfExprTypeLoc loc) {
    auto t = loc.getTypePtr()->desugar();
    auto required_by = dependencies(loc.getTypePtr()->getUnderlyingExpr());
    if (required_by.empty()) return TraverseType(t);
    auto begin = loc.getBeginLoc();
    auto end = Lexer::getLocForEndOfToken(loc.getEndLoc(), 0, sm, ctx.getLangOpts());
    auto node = "prune-expression:" + file(begin) + ":" + std::to_string(offset(begin));
    out.conditional_changes[node].dependencies.insert(required_by.begin(), required_by.end());
    if (!callable(t) && printableType(t) && editable(begin) && editable(end)) {
      // C2Rust exports the resulting type, not this operand. It may mention
      // declarations removed by retention or calls whose signatures change.
      out.conditional_changes[node].edits.push_back(edit(begin, end,
          "__typeof__(" + t.getAsString(ctx.getPrintingPolicy()) + ")", "prune-expression"));
    } else {
      out.conditional_changes[node].blockers.insert("source-unsupported-typeof-rewrite");
      out.unprunable_declarations.push_back(Object{{"kind", "unsupported-typeof-rewrite"},
          {"site", site(begin)}});
    }
    return TraverseType(t);
  }
  bool TraverseConstantArrayType(ConstantArrayType *t) { return TraverseType(t->getElementType()); }
  bool TraverseConstantArrayTypeLoc(ConstantArrayTypeLoc loc) {
    if (auto *bound = loc.getSizeExpr(); bound && !isa<IntegerLiteral>(bound->IgnoreParenImpCasts())) {
      auto required_by = dependencies(bound);
      if (required_by.empty()) return TraverseTypeLoc(loc.getElementLoc());
      auto begin = bound->getBeginLoc();
      auto end = Lexer::getLocForEndOfToken(bound->getEndLoc(), 0, sm, ctx.getLangOpts());
      auto node = "prune-expression:" + file(begin) + ":" + std::to_string(offset(begin));
      out.conditional_changes[node].dependencies.insert(required_by.begin(), required_by.end());
      if (editable(begin) && editable(end)) {
        out.conditional_changes[node].edits.push_back(edit(begin, end,
            std::to_string(loc.getTypePtr()->getSize().getLimitedValue()) + "ULL", "prune-expression"));
      } else {
        out.conditional_changes[node].blockers.insert("source-uneditable-constant-array-bound");
        out.unprunable_declarations.push_back(Object{{"kind", "uneditable-constant-array-bound"},
            {"site", site(begin)}});
      }
    }
    return TraverseTypeLoc(loc.getElementLoc());
  }
  SourceLocation declarationTerminator(SourceLocation from) {
    // Clang's TypedefDecl extent can end at the identifier, before trailing
    // GNU attributes (notably libc's register_t mode attribute). Find the
    // physical semicolon, respecting nested attribute/asm expressions.
    unsigned nesting = 0;
    for (unsigned count = 0; count < 4096; ++count) {
      auto next = Lexer::findNextToken(from, sm, ctx.getLangOpts());
      if (!next || next->is(tok::eof) || !editable(next->getLocation())) break;
      if (next->is(tok::semi) && nesting == 0) return next->getLocation().getLocWithOffset(1);
      if (next->isOneOf(tok::l_paren, tok::l_square, tok::l_brace)) ++nesting;
      if (next->isOneOf(tok::r_paren, tok::r_square, tok::r_brace) && nesting) --nesting;
      from = next->getLocation();
    }
    return {};
  }
  void recordPruning() {
    // Discarded bodies/initializers must not leave invalid C behind when a
    // selected recipe removes a global or changes a function's signature.
    // Emit deletions, applied only when localization is materialized.
    std::map<unsigned, std::vector<Decl *>> starts;
    for (auto *d : ctx.getTranslationUnitDecl()->decls()) {
      if (d->isImplicit() || !editable(d->getBeginLoc())) continue;
      if (isa<FunctionDecl>(d) || isa<VarDecl>(d) || isa<TagDecl>(d) || isa<TypedefNameDecl>(d))
        starts[offset(d->getBeginLoc())].push_back(d);
    }
    // A typedef and its embedded tag have different begin offsets but overlap.
    // Treat the entire physical declaration as one group, or we'd both produce
    // conflicting deletions and risk deleting a retained tag with an unused alias.
    std::vector<std::vector<Decl *>> groups;
    unsigned group_end = 0;
    for (auto &entry : starts) {
      if (groups.empty() || entry.first >= group_end) groups.emplace_back();
      for (auto *d : entry.second) {
        groups.back().push_back(d);
        auto after = Lexer::getLocForEndOfToken(d->getEndLoc(), 0, sm, ctx.getLangOpts());
        group_end = std::max(group_end, offset(after));
      }
    }
    struct PlannedPruning {
      std::vector<Decl *> declarations;
      std::string node;
    };
    std::vector<PlannedPruning> planned;
    for (auto &group : groups) {
      unsigned variable_count = 0;
      for (auto *d : group) variable_count += isa<VarDecl>(d);
      if (variable_count > 1)
        for (auto *d : group) if (auto *v = dyn_cast<VarDecl>(d))
          out.nodes["global:" + v->getNameAsString()].blockers.insert("source-joined-global-declaration");
      bool kept = false, discarded = false, types_only = true;
      for (auto *d : group) {
        kept |= retention.contains(d);
        discarded |= !retention.contains(d);
        types_only &= isa<TagDecl>(d) || isa<TypedefNameDecl>(d);
        if (!retention.contains(d)) {
          auto *named = dyn_cast<NamedDecl>(d);
          out.pruned_declarations.push_back(Object{{"name", named ? named->getNameAsString() : ""},
              {"file", file(d->getLocation())}, {"offset", offset(d->getLocation())},
              {"kind", d->getDeclKindName()}});
        }
      }
      if (!discarded) continue;
      PhysicalPruning physical;
      for (auto *d : group) if (!retention.contains(d)) physical.TraverseDecl(d);
      if (!physical.required) continue;
      auto begin = group.front()->getBeginLoc();
      auto node = "prune-declaration:" + file(begin) + ":" + std::to_string(offset(begin));
      for (auto *d : group)
        if (!retention.contains(d)) pruning_nodes[d->getCanonicalDecl()] = node;
      planned.push_back({group, node});
      if (kept) {
        // The discarded portion cannot be removed independently. Only a plan
        // which would invalidate it is blocked.
        if (!types_only) {
          out.conditional_changes[node].blockers.insert("source-mixed-declaration-group");
          out.unprunable_declarations.push_back(Object{{"kind", "mixed-declaration-group"},
              {"site", site(group.front()->getBeginLoc())}});
        }
        continue;
      }
      SourceLocation end;
      bool complete = true;
      for (auto *d : group) {
        auto after = Lexer::getLocForEndOfToken(d->getEndLoc(), 0, sm, ctx.getLangOpts());
        if (auto *f = dyn_cast<FunctionDecl>(d); !f || !f->doesThisDeclarationHaveABody()) {
          auto semi = declarationTerminator(d->getEndLoc());
          if (semi.isValid()) after = semi;
          else {
            complete = false;
            out.unprunable_declarations.push_back(Object{{"kind", "missing-terminator"},
                {"site", site(d->getEndLoc())}, {"declaration_kind", d->getDeclKindName()}});
            continue;
          }
        }
        if (end.isInvalid() || offset(after) > offset(end)) end = after;
      }
      if (complete && begin.isValid() && end.isValid()) {
        out.conditional_changes[node].edits.push_back(edit(begin, end, "", "prune-declaration"));
      } else {
        out.conditional_changes[node].blockers.insert("source-missing-declaration-terminator");
      }
    }
    // A discarded declaration only needs physical removal if localization
    // changes something in its syntax. Dependencies on another discarded
    // declaration propagate that requirement through these pruning nodes.
    for (auto &entry : planned) {
      DependencyCollector collector;
      for (auto *d : entry.declarations)
        if (!retention.contains(d)) collector.TraverseDecl(d);
      auto dependencies = dependencyNodes(collector.declarations);
      dependencies.erase(entry.node);
      out.conditional_changes[entry.node].dependencies.insert(dependencies.begin(), dependencies.end());
    }
  }
  bool TraverseFunctionDecl(FunctionDecl *d) {
    auto saved = function;
    function = d->getNameAsString();
    bool ok = RecursiveASTVisitor::TraverseFunctionDecl(d);
    function = saved; return ok;
  }
  bool TraverseVarDecl(VarDecl *d) {
    auto saved = initializer;
    if (d->hasGlobalStorage()) initializer = d->getNameAsString();
    bool ok = RecursiveASTVisitor::TraverseVarDecl(d);
    initializer = saved; return ok;
  }
  bool VisitNamedDecl(NamedDecl *d) {
    out.identifiers.insert(d->getNameAsString()); return true;
  }
  bool VisitRecordDecl(RecordDecl *r) {
    if (!r->isCompleteDefinition() || r->isInvalidDecl()) return true;
    const auto &layout = ctx.getASTRecordLayout(r);
    Array fields;
    unsigned i = 0;
    for (auto *f : r->fields()) {
      fields.push_back(Object{{"name", f->getNameAsString()},
          {"type", typeSignature(f->getType())},
          {"bit_width", f->isBitField() ? static_cast<int64_t>(f->getBitWidthValue(ctx)) : -1},
          {"offset_bits", static_cast<int64_t>(layout.getFieldOffset(i++))}});
      if (r->isUnion() && callable(f->getType()))
        out.nodes[id(f)].blockers.insert("source-union-callable-storage");
    }
    out.records.push_back(Object{{"id", recordId(r)},
        {"fields", std::move(fields)}, {"size", layout.getSize().getQuantity()},
        {"alignment", layout.getAlignment().getQuantity()}});
    return true;
  }
  bool VisitFunctionDecl(FunctionDecl *f) {
    auto n = id(f);
    auto &node = out.nodes[n];
    auto name = f->getNameAsString();
    auto loc = f->getLocation();
    wrapper(f);
    out.functions.push_back(Object{{"name", name}, {"defined", f->isThisDeclarationADefinition()},
      {"file", file(loc)}, {"offset", offset(loc)},
      {"internal", !f->isExternallyVisible()},
      {"external_inline", f->isInlined() && f->isExternallyVisible()}});
    if (f->isInlined() && f->isExternallyVisible())
      node.blockers.insert("source-external-inline-definition");
    if (f->hasAttr<ConstructorAttr>() || f->hasAttr<DestructorAttr>() ||
        f->hasAttr<AliasAttr>() || f->hasAttr<AsmLabelAttr>() || f->hasAttr<UsedAttr>())
      node.blockers.insert("source-lifecycle-or-opaque-entry");
    if (name != "main" && f->getTypeSourceInfo())
      typeEdits(n, f->getTypeSourceInfo()->getTypeLoc(), true);
    if (name == "main" && !f->isThisDeclarationADefinition())
      node.blockers.insert("source-main-redeclaration");
    for (auto *p : f->parameters()) if (callable(p->getType())) {
      auto pn = id(p); out.nodes[pn];
      // Escape is decided after joining definitions from every TU.
      out.edges.push_back(Array{pn, "boundary:" + name});
    }
    if (callable(f->getReturnType())) {
      auto rn = "return:" + name;
      out.nodes[rn].blockers.insert("source-callable-return-type");
      out.edges.push_back(Array{rn, "boundary:" + name});
    }
    return true;
  }
  // Check that a generated file-scope prototype can name this type here.
  bool wrapperTypeVisible(QualType t, SourceLocation before) {
    if (auto *alias = dyn_cast<TypedefType>(t.getTypePtr())) {
      auto *d = alias->getDecl();
      return d->getDeclContext()->isTranslationUnit() && offset(d->getLocation()) < offset(before);
    }
    if (auto *tag = t->getAs<TagType>()) {
      auto *d = tag->getDecl()->getCanonicalDecl();
      return d->getDeclContext()->isTranslationUnit() && offset(d->getLocation()) < offset(before);
    }
    if (t->isPointerType()) return wrapperTypeVisible(t->getPointeeType(), before);
    if (auto *a = ctx.getAsArrayType(t)) return wrapperTypeVisible(a->getElementType(), before);
    return t->isBuiltinType();
  }
  // One declaration per TU, and a candidate definition after all source types
  // are complete. The planner chooses one definition for each external symbol.
  void wrapper(FunctionDecl *f) {
    if (!wrapper_declarations.insert(f->getCanonicalDecl()).second) return;
    auto name = f->getNameAsString();
    auto begin = f->getBeginLoc();
    auto end = sm.getLocForEndOfFile(sm.getMainFileID());
    Array blockers;
    auto *proto = f->getType()->getAs<FunctionProtoType>();
    if (!proto || proto->isVariadic() || proto->getCallConv() != CC_C ||
        callable(f->getReturnType()))
      blockers.push_back("source-unsupported-wrapper-signature");
    for (auto *p : f->parameters())
      if (callable(p->getType()) || !printableType(p->getType()) || !wrapperTypeVisible(p->getType(), begin))
        blockers.push_back("source-unsupported-wrapper-signature");
    if (!printableType(f->getReturnType()) || !wrapperTypeVisible(f->getReturnType(), begin))
      blockers.push_back("source-unsupported-wrapper-signature");
    if (!f->getDeclContext()->isTranslationUnit() || !editable(begin))
      blockers.push_back("source-wrapper-declaration-scope");
    for (auto *decl : f->redecls()) {
      if (decl->hasAttr<AliasAttr>() || decl->hasAttr<WeakAttr>() || decl->hasAttr<WeakRefAttr>() ||
          decl->hasAttr<AsmLabelAttr>() || decl->hasAttr<IFuncAttr>())
        blockers.push_back("source-wrapper-symbol-alias");
      if (decl->hasAttr<ReturnsTwiceAttr>())
        blockers.push_back("source-wrapper-returns-twice");
    }
    std::string params = "struct XjGlobals *xjg", args;
    for (unsigned i = 0; i < f->getNumParams(); ++i) {
      auto arg = "_xjw_arg_" + std::to_string(i);
      std::string parameter;
      llvm::raw_string_ostream stream(parameter);
      f->getParamDecl(i)->getType().print(stream, ctx.getPrintingPolicy(), arg);
      stream.flush();
      params += ", " + parameter;
      if (i) args += ", ";
      args += arg;
    }
    std::string signature;
    llvm::raw_string_ostream stream(signature);
    f->getReturnType().print(stream, ctx.getPrintingPolicy(), name + "_xjw(" + params + ")");
    stream.flush();
    if (!f->isExternallyVisible()) signature = "static " + signature;
    auto body = "\n" + signature + " { (void)xjg; " +
        (f->getReturnType()->isVoidType() ? "" : "return ") + name + "(" + args + "); }\n";
    out.wrappers.push_back(Object{{"function", name}, {"internal", !f->isExternallyVisible()},
      {"blockers", std::move(blockers)},
      {"declaration", edit(begin, begin, "\n" + signature + ";\n", "wrapper-declaration")},
      {"definition", edit(end, end, body, "wrapper-definition")}});
  }
  bool VisitDeclaratorDecl(DeclaratorDecl *d) {
    if (isa<FunctionDecl>(d) || !typed.insert(d).second) return true;
    if (d->getName() == "xjg" || d->getName() == "xjgv")
      if (!function.empty()) out.nodes["fn:" + function].blockers.insert("source-context-name-collision");
    if (callable(d->getType())) {
      auto n = id(d); out.nodes[n];
      if (d->getTypeSourceInfo()) typeEdits(n, d->getTypeSourceInfo()->getTypeLoc(), false);
      else out.nodes[n].blockers.insert("source-missing-callable-typeloc");
      QualType t = d->getType().getCanonicalType();
      if (t->isPointerType() && t->getPointeeType()->isPointerType())
        out.nodes[n].blockers.insert("source-pointer-indirection");
    }
    return true;
  }
  bool VisitVarDecl(VarDecl *d) {
    if (d->hasGlobalStorage()) {
      const bool definition = d->isThisDeclarationADefinition();
      if (definition) out.globals.insert(d->getNameAsString());
      Array slots;
      std::set<std::string> features;
      initializerFeatures(d->getInit(), features);
      if (d->hasInit() && (d->getType()->isSpecificBuiltinType(BuiltinType::LongDouble) ||
                         d->getType()->isSpecificBuiltinType(BuiltinType::Float128)))
        features.insert("extended-float-initializer");
      Array feature_array;
      for (auto &feature : features) feature_array.push_back(feature);
      Array initializer_functions;
      initializerFunctions(d->getInit(), initializer_functions);
      if (callable(d->getType())) slots.push_back(id(d));
      else for (auto &n : aggregate(d->getType())) slots.push_back(n);
      out.variables.push_back(Object{{"name", d->getNameAsString()}, {"id", id(d)},
          {"signature", typeSignature(d->getType())}, {"defined", definition},
          {"declaration", function.empty() ? d->getNameAsString() : function + ":" + d->getNameAsString()},
          {"site", site(d->getLocation())},
          {"contains_object_pointer", containsObjectPointer(d->getType())},
          {"initializer_features", std::move(feature_array)},
          {"initializer_functions", std::move(initializer_functions)},
          {"callable_nodes", std::move(slots)}});
      if (d->hasInit()) out.initialized.insert(d->getNameAsString());
      if (d->isThisDeclarationADefinition() && !d->hasInit())
        out.no_initializer.insert(d->getNameAsString());
      if (d->getTLSKind() != VarDecl::TLS_None)
        out.nodes["global:" + d->getNameAsString()].blockers.insert("source-thread-local-storage");
    }
    init(id(d), d->getType(), d->getInit()); return true;
  }
  bool VisitDeclStmt(DeclStmt *s) {
    if (!s->isSingleDecl()) for (auto *d : s->decls())
      if (auto *v = dyn_cast<VarDecl>(d); v && v->hasGlobalStorage())
        out.nodes["global:" + v->getNameAsString()].blockers.insert("source-joined-global-declaration");
    return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *e) {
    if (auto *g = dyn_cast<VarDecl>(e->getDecl())) if (g->hasGlobalStorage()) {
      Object use{{"global", g->getNameAsString()}, {"function", function},
                 {"initializer", initializer}, {"file", file(e->getBeginLoc())},
                 {"offset", offset(e->getBeginLoc())}, {"observations", observations(e)}};
      out.uses.push_back(std::move(use));
    }
    return true;
  }
  bool VisitBinaryOperator(BinaryOperator *e) {
    if (e->isAssignmentOp() || e->isComparisonOp()) {
      auto left = values(e->getLHS()), right = values(e->getRHS());
      connect(left, right);
      if (e->isAssignmentOp() && !callable(e->getLHS()->getType()))
        for (auto &n : right) out.nodes[n].blockers.insert("source-opaque-callable-store");
      if (e->getLHS()->getType()->isRecordType()) {
        // A compound literal exposes the value assigned to each callback field;
        // an ordinary aggregate copy does not.
        if (isa<CompoundLiteralExpr>(e->getRHS()->IgnoreParenImpCasts()))
          init("", e->getLHS()->getType(), e->getRHS());
        else
          blockAggregate(e->getLHS()->getType(), "source-aggregate-copy");
      }
    }
    return true;
  }
  bool VisitExplicitCastExpr(ExplicitCastExpr *e) {
    values(e); return true; // Never let a cast hide a changed ABI.
  }
  bool VisitCastExpr(CastExpr *e) {
    auto from = aggregate(e->getSubExpr()->getType());
    auto to = aggregate(e->getType());
    if (std::set<std::string>(from.begin(), from.end()) !=
        std::set<std::string>(to.begin(), to.end())) {
      // In particular, record-pointer <-> void* conversions can conceal
      // consumers with a different callback field type. Separate C parsing
      // cannot catch the resulting ABI mismatch after a signature change.
      for (const auto &n : from) out.nodes[n].blockers.insert("source-opaque-aggregate-cast");
      for (const auto &n : to) out.nodes[n].blockers.insert("source-opaque-aggregate-cast");
    }
    return true;
  }
  bool VisitReturnStmt(ReturnStmt *r) {
    auto a = values(r->getRetValue());
    if (!a.empty()) connect({"return:" + function}, a);
    return true;
  }
  bool VisitAsmStmt(AsmStmt *s) {
    blockOpaqueOperands(s, "source-inline-assembly");
    out.nodes["fn:" + function].blockers.insert("source-inline-assembly"); return true;
  }
  bool VisitCallExpr(CallExpr *c) {
    auto *direct = c->getDirectCallee();
    auto targets = direct ? std::vector<std::string>{id(direct)} : values(c->getCallee());
    for (unsigned i = 0; i < c->getNumArgs(); ++i) {
      auto *arg = c->getArg(i);
      auto a = values(arg);
      auto fields = aggregate(arg->IgnoreParenImpCasts()->getType());
      if (a.empty() && fields.empty()) continue;
      if (direct && i < direct->getNumParams()) {
        auto pn = id(direct->getParamDecl(i));
        connect(a, {pn});
        out.edges.push_back(Array{pn, "boundary:" + direct->getNameAsString()});
        if (!callable(direct->getParamDecl(i)->getType()))
          for (auto &n : a) out.nodes[n].blockers.insert("source-opaque-callable-transfer");
        const auto expected = aggregate(direct->getParamDecl(i)->getType());
        for (auto &n : fields) {
          out.edges.push_back(Array{n, "boundary:" + direct->getNameAsString()});
          if (std::find(expected.begin(), expected.end(), n) == expected.end())
            out.nodes[n].blockers.insert("source-opaque-aggregate-transfer");
        }
      } else {
        a.insert(a.end(), fields.begin(), fields.end());
        for (auto &n : a) out.nodes[n].blockers.insert("source-indirect-or-variadic-callback-transfer");
      }
    }
    if (function.empty() || !initializer.empty()) {
      for (auto &n : targets) out.nodes[n].blockers.insert("source-initializer-call");
      return true;
    }
    auto end = c->getRParenLoc();
    auto left = Lexer::findNextToken(c->getCallee()->getEndLoc(), sm, ctx.getLangOpts());
    if (!left || !left->is(tok::l_paren) || !editable(left->getLocation()) || !editable(end)) {
      for (auto &n : targets) out.nodes[n].blockers.insert("source-uneditable-call");
      return true;
    }
    auto begin = left->getLocation();
    Array ts; for (auto &n : targets) { out.nodes[n]; ts.push_back(n); }
    auto loc = sm.getSpellingLoc(c->getBeginLoc());
    out.calls.push_back(Object{{"caller", function}, {"targets", std::move(ts)},
      {"file", file(loc)}, {"line", sm.getSpellingLineNumber(loc)},
      {"col", sm.getSpellingColumnNumber(loc)}, {"offset", offset(loc)},
      {"edit", edit(begin, begin.getLocWithOffset(1), std::string("(((struct XjGlobals*)0)") +
                        (c->getNumArgs() ? ", " : ""), "call")}});
    return true;
  }
};

class Consumer : public ASTConsumer {
  Facts &facts;
public:
  explicit Consumer(Facts &facts) : facts(facts) {}
  void HandleTranslationUnit(ASTContext &ctx) override {
    Retention retention(ctx);
    Extract extractor(ctx, facts, retention);
    extractor.recordPruning();
    extractor.TraverseDecl(ctx.getTranslationUnitDecl());
  }
};
class Action : public ASTFrontendAction {
  Facts &facts;
public:
  explicit Action(Facts &facts) : facts(facts) {}
  bool BeginSourceFileAction(CompilerInstance &ci) override {
    if (ci.getLangOpts().CPlusPlus) {
      auto id = ci.getDiagnostics().getCustomDiagID(DiagnosticsEngine::Error,
                                                   "PANGS source planning currently requires C");
      ci.getDiagnostics().Report(id); return false;
    }
    return true;
  }
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &ci, llvm::StringRef) override {
    return std::make_unique<Consumer>(facts);
  }
};
class Factory : public FrontendActionFactory {
  Facts &facts;
public:
  explicit Factory(Facts &facts) : facts(facts) {}
  std::unique_ptr<FrontendAction> create() override { return std::make_unique<Action>(facts); }
};

bool parseCommand(const CompileCommand &command, Factory &factory, Facts &facts) {
  // ClangTool 14 filters out cpp-output (.i) jobs. Build the driver's one cc1
  // invocation ourselves so preprocessed input is not re-preprocessed as C.
  // A private VFS honors command cwd without changing the process cwd.
  llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> vfs = llvm::vfs::createPhysicalFileSystem();
  if (vfs->setCurrentWorkingDirectory(command.Directory)) return false;
  llvm::IntrusiveRefCntPtr<DiagnosticOptions> options(new DiagnosticOptions);
  auto *printer = new TextDiagnosticPrinter(llvm::errs(), options.get());
  llvm::IntrusiveRefCntPtr<DiagnosticsEngine> diagnostics(
      new DiagnosticsEngine(new DiagnosticIDs, options, printer));
  auto args = getClangStripOutputAdjuster()(command.CommandLine, command.Filename);
  args = getClangSyntaxOnlyAdjuster()(args, command.Filename);
  args = getClangStripDependencyFileAdjuster()(args, command.Filename);
  args.push_back("-Werror=incompatible-function-pointer-types");
  if (args.empty()) return false;
  driver::Driver driver(args.front(), llvm::sys::getDefaultTargetTriple(), *diagnostics, "clang", vfs);
  llvm::SmallVector<const char *, 32> argv;
  for (auto &arg : args) argv.push_back(arg.c_str());
  std::unique_ptr<driver::Compilation> compilation(driver.BuildCompilation(argv));
  if (!compilation || compilation->getJobs().size() != 1 || diagnostics->hasErrorOccurred()) return false;
  const auto &job = *compilation->getJobs().begin();
  const auto &cc1 = job.getArguments();
  if (cc1.empty() || llvm::StringRef(cc1.front()) != "-cc1") return false;
  Array cc1_args;
  // llvm::json keeps const char* as a borrowed StringRef. Driver arguments
  // die with Compilation, so explicitly own every retained string.
  for (auto *arg : cc1) cc1_args.push_back(std::string(arg));
  facts.invocations.push_back(Object{{"file", command.Filename}, {"directory", command.Directory},
                                    {"cc1", std::move(cc1_args)}});
  auto invocation = std::make_shared<CompilerInvocation>();
  if (!CompilerInvocation::CreateFromArgs(*invocation, llvm::ArrayRef<const char *>(cc1).drop_front(),
                                         *diagnostics, args.front().c_str())) return false;
  invocation->getFrontendOpts().DisableFree = false;
  invocation->getCodeGenOpts().DisableFree = false;
  FileSystemOptions fs_options;
  fs_options.WorkingDir = command.Directory;
  llvm::IntrusiveRefCntPtr<FileManager> files(new FileManager(fs_options, vfs));
  return factory.runInvocation(invocation, files.get(), std::make_shared<PCHContainerOperations>(), nullptr);
}
}

extern "C" char *pangs_source_extract(const char *database) {
  std::string error;
  auto db = JSONCompilationDatabase::loadFromFile(database, error, JSONCommandLineSyntax::AutoDetect);
  Object result;
  if (!db) result["error"] = error;
  else {
    Facts facts;
    Factory factory(facts);
    auto files = db->getAllFiles();
    std::sort(files.begin(), files.end());
    bool ok = !files.empty();
    for (const auto &file : files) {
      if (db->getCompileCommands(file).size() != 1) { ok = false; break; }
      if (!parseCommand(db->getCompileCommands(file).front(), factory, facts)) { ok = false; break; }
    }
    if (!ok) result["error"] = "source parse failed, empty database, or multiple command variants";
    else {
      if (facts.globals.count("xjg") || facts.globals.count("xjgv") ||
          facts.identifiers.count("XjGlobals") || facts.nodes.count("fn:xjg"))
        for (auto &g : facts.globals)
          facts.nodes["global:" + g].blockers.insert("source-context-name-collision");
      for (auto &entry : facts.clone_users) if (facts.identifiers.count(entry.first))
        for (auto &node : entry.second) facts.nodes[node].blockers.insert("source-generated-name-collision");
      Object nodes;
      for (auto &entry : facts.nodes) {
        Array blockers; for (auto &b : entry.second.blockers) blockers.push_back(b);
        nodes[entry.first] = Object{{"function", entry.second.function},
          {"blockers", std::move(blockers)}, {"edits", std::move(entry.second.edits)}};
      }
      Object conditional_changes;
      for (auto &entry : facts.conditional_changes) {
        Array dependencies, blockers;
        for (auto &d : entry.second.dependencies) dependencies.push_back(d);
        for (auto &b : entry.second.blockers) blockers.push_back(b);
        conditional_changes[entry.first] = Object{{"dependencies", std::move(dependencies)},
          {"blockers", std::move(blockers)}, {"edits", std::move(entry.second.edits)}};
      }
      Array globals, no_initializer;
      Object producers;
      for (auto &entry : facts.producers) producers[entry.first] = std::move(entry.second);
      for (auto &value : facts.wrappers) {
        auto &w = *value.getAsObject();
        if (facts.identifiers.count(w.getString("function")->str() + "_xjw"))
          w.getArray("blockers")->push_back("source-generated-name-collision");
      }
      for (auto &g : facts.globals) globals.push_back(g);
      for (auto &g : facts.no_initializer) if (!facts.initialized.count(g)) no_initializer.push_back(g);
      result = Object{{"nodes", std::move(nodes)},
        {"conditional_changes", std::move(conditional_changes)}, {"edges", std::move(facts.edges)},
        {"producers", std::move(producers)}, {"wrappers", std::move(facts.wrappers)},
        {"calls", std::move(facts.calls)}, {"uses", std::move(facts.uses)},
        {"functions", std::move(facts.functions)}, {"records", std::move(facts.records)},
        {"variables", std::move(facts.variables)}, {"invocations", std::move(facts.invocations)},
        {"pruned_declarations", std::move(facts.pruned_declarations)},
        {"unprunable_declarations", std::move(facts.unprunable_declarations)},
        {"globals", std::move(globals)},
        {"no_initializer", std::move(no_initializer)},
        {"compiler", getClangFullVersion()}};
    }
  }
  std::string buffer;
  llvm::raw_string_ostream stream(buffer); stream << Value(std::move(result)); stream.flush();
  return ::strdup(buffer.c_str());
}
extern "C" void pangs_source_free(char *result) { std::free(result); }
