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
struct Facts {
  std::map<std::string, Node> nodes;
  Array edges, calls, uses, functions, records, variables, invocations;
  std::set<std::string> globals, mutable_storage, identifiers, no_initializer, initialized;
  std::map<std::string, std::set<std::string>> clone_users;
};

class Extract : public RecursiveASTVisitor<Extract> {
  ASTContext &ctx;
  SourceManager &sm;
  Facts &out;
  std::string function, initializer;
  std::set<const Decl *> typed;
  unsigned unknown_count = 0;

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
                  {"end", offset(end)}, {"expected", text(begin, end)},
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
    if (auto *d = dyn_cast<DeclRefExpr>(s)) {
      if (callable(d->getType())) result.push_back(id(d->getDecl()));
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
    if (auto *d = dyn_cast<DeclRefExpr>(e)) {
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
    if (auto *e = dyn_cast<Expr>(s)) {
      for (auto &n : values(e)) out.nodes[n].blockers.insert(reason);
      blockAggregate(e->getType(), reason);
    }
    for (auto *child : s->children()) blockOpaqueOperands(child, reason);
  }
  bool ordinaryRead(const Expr *e) {
    // Follow the lvalue through array/record selection and parentheses. A read
    // of table[i] does not require mutable storage merely because table decays.
    for (unsigned depth = 0; depth < 64; ++depth) {
      auto parents = ctx.getParents(*e);
      if (parents.size() != 1) return false;
      if (auto *cast = parents[0].get<ImplicitCastExpr>()) {
        if (cast->getCastKind() == CK_LValueToRValue) return true;
        if (cast->getCastKind() != CK_ArrayToPointerDecay && cast->getCastKind() != CK_NoOp)
          return false;
        e = cast;
      } else if (auto *paren = parents[0].get<ParenExpr>()) e = paren;
      else if (auto *member = parents[0].get<MemberExpr>()) {
        if (member->isArrow()) return false;
        e = member;
      } else if (auto *subscript = parents[0].get<ArraySubscriptExpr>()) e = subscript;
      else if (auto *unary = parents[0].get<UnaryOperator>()) {
        if (unary->getOpcode() != UO_Deref) return false;
        e = unary;
      } else if (parents[0].get<UnaryExprOrTypeTraitExpr>()) return true;
      else return false;
    }
    return false;
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
        auto begin = left.getLocWithOffset(1);
        // No parameters: replace all whitespace and the optional `void` token.
        auto end = fn.getNumParams() ? begin : right;
        std::string arg = named ? "struct XjGlobals *xjg" : "struct XjGlobals *";
        if (fn.getNumParams()) arg += ", ";
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
  Extract(ASTContext &ctx, Facts &out) : ctx(ctx), sm(ctx.getSourceManager()), out(out) {}
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
    out.functions.push_back(Object{{"name", name}, {"defined", f->isThisDeclarationADefinition()},
      {"file", file(loc)}, {"offset", offset(loc)},
      {"internal", !f->isExternallyVisible()},
      {"external_inline", f->isInlined() && f->isExternallyVisible()},
      {"signature", typeSignature(f->getType())}});
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
      if (callable(d->getType())) slots.push_back(id(d));
      else for (auto &n : aggregate(d->getType())) slots.push_back(n);
      out.variables.push_back(Object{{"name", d->getNameAsString()}, {"id", id(d)},
          {"signature", typeSignature(d->getType())}, {"defined", definition},
          {"callable_nodes", std::move(slots)}});
      if (d->hasInit()) out.initialized.insert(d->getNameAsString());
      if (d->isThisDeclarationADefinition() && !d->hasInit())
        out.no_initializer.insert(d->getNameAsString());
      if (d->getTLSKind() != VarDecl::TLS_None)
        out.nodes["global:" + d->getNameAsString()].blockers.insert("source-thread-local-storage");
    }
    init(id(d), d->getType(), d->getInit()); return true;
  }
  bool VisitDeclRefExpr(DeclRefExpr *e) {
    if (auto *g = dyn_cast<VarDecl>(e->getDecl())) if (g->hasGlobalStorage()) {
      Object use{{"global", g->getNameAsString()}, {"function", function},
                 {"initializer", initializer}, {"file", file(e->getBeginLoc())},
                 {"offset", offset(e->getBeginLoc())}};
      out.uses.push_back(std::move(use));
      // A retained lvalue which is not an ordinary read may be written through,
      // including through a call omitted by IR. This is representation evidence,
      // deliberately not a semantic runtime-written fact.
      if (!ordinaryRead(e))
        out.mutable_storage.insert(g->getNameAsString());
    }
    return true;
  }
  bool VisitBinaryOperator(BinaryOperator *e) {
    if (e->isAssignmentOp() || e->isComparisonOp()) {
      auto left = values(e->getLHS()), right = values(e->getRHS());
      connect(left, right);
      if (e->isAssignmentOp() && !callable(e->getLHS()->getType()))
        for (auto &n : right) out.nodes[n].blockers.insert("source-opaque-callable-store");
      if (e->getLHS()->getType()->isRecordType())
        blockAggregate(e->getLHS()->getType(), "source-aggregate-copy");
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
    auto targets = values(c->getCallee());
    auto *direct = c->getDirectCallee();
    if (direct) targets = {id(direct)};
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
    auto begin = left->getLocation().getLocWithOffset(1);
    Array ts; for (auto &n : targets) { out.nodes[n]; ts.push_back(n); }
    auto loc = sm.getSpellingLoc(c->getBeginLoc());
    out.calls.push_back(Object{{"caller", function}, {"targets", std::move(ts)},
      {"file", file(loc)}, {"line", sm.getSpellingLineNumber(loc)},
      {"col", sm.getSpellingColumnNumber(loc)}, {"offset", offset(loc)},
      {"edit", edit(begin, begin, std::string("((struct XjGlobals*)0)") +
                        (c->getNumArgs() ? ", " : ""), "call")}});
    return true;
  }
};

class Consumer : public ASTConsumer {
  Facts &facts;
public:
  explicit Consumer(Facts &facts) : facts(facts) {}
  void HandleTranslationUnit(ASTContext &ctx) override {
    Extract(ctx, facts).TraverseDecl(ctx.getTranslationUnitDecl());
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
      Array globals, mutable_storage, no_initializer;
      for (auto &g : facts.globals) globals.push_back(g);
      for (auto &g : facts.mutable_storage) mutable_storage.push_back(g);
      for (auto &g : facts.no_initializer) if (!facts.initialized.count(g)) no_initializer.push_back(g);
      result = Object{{"nodes", std::move(nodes)}, {"edges", std::move(facts.edges)},
        {"calls", std::move(facts.calls)}, {"uses", std::move(facts.uses)},
        {"functions", std::move(facts.functions)}, {"records", std::move(facts.records)},
        {"variables", std::move(facts.variables)}, {"invocations", std::move(facts.invocations)},
        {"globals", std::move(globals)},
        {"mutable_storage", std::move(mutable_storage)}, {"no_initializer", std::move(no_initializer)},
        {"compiler", getClangFullVersion()}};
    }
  }
  std::string buffer;
  llvm::raw_string_ostream stream(buffer); stream << Value(std::move(result)); stream.flush();
  return ::strdup(buffer.c_str());
}
extern "C" void pangs_source_free(char *result) { std::free(result); }
