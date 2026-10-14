# In plain English: the engine behind the "allowed code" guardrail (tests/test_allowed_code.py). It reads one Python file and lists
# everything the file USES: what it imports, what it calls, which attributes it reads, which built-in names it touches, which keyword
# names it passes and which errors it catches. The guardrail then compares that list with the allowed list written out for that file
# in tests/allowed_table.py. Anything used but not listed is a problem, and so is anything listed but not used (a stale allowance
# would quietly permit a future change). Nothing here tries to recognise "bad" code: it only knows what is allowed.
import ast
import builtins

BUILTIN_NAMES = set(dir(builtins))
SETTING_READERS = {"environment.get", "os.environ.get", "os.getenv"}


# In plain English: every name that ONE piece of code binds, meaning gives a value to, declares, imports, defines or deletes.
# This list is Python's own: it covers every syntax tree node type that can carry a name (tests/test_fixed_destinations.py checks the
# list against the language itself, so a new kind of binding added by a future Python makes a test fail instead of slipping by).
def names_bound_by(node):
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return {node.id}  # =, :=, +=, for, with ... as, comprehensions, del, tuple and star unpacking
    if isinstance(node, ast.arg):
        return {node.arg}  # every parameter of a def or a lambda, including *args, **kwargs, keyword-only and positional-only
    if isinstance(node, ast.ExceptHandler):
        return {node.name} if node.name else set()  # except ... as name, except* ... as name
    if isinstance(node, ast.alias):
        return {(node.asname or node.name).split(".")[0]}  # import x, import x as y, from x import y [as z]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return {node.name}
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return {node.name} if node.name else set()
    if isinstance(node, ast.MatchMapping):
        return {node.rest} if node.rest else set()
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return set(node.names)  # declaring that a name is rebound from inside a function is itself a re-binding
    if type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple"):
        return {node.name}  # def f[NAME](): ...  and  class C[NAME]: ...
    return set()


# In plain English: the import written the way it is spelled, one text per name, so "from x import y as z" and "import x" are
# different allowances and an alias can never be added quietly.
def import_texts(node):
    if isinstance(node, ast.Import):
        return {f"import {a.name}" + (f" as {a.asname}" if a.asname else "") for a in node.names}
    module = "." * node.level + (node.module or "")
    return {f"from {module} import {a.name}" + (f" as {a.asname}" if a.asname else "") for a in node.names}


def _function_name(node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return "<module>"


def _caught(handler):
    if handler.type is None:
        return ["BARE"]
    kinds = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    return sorted(ast.unparse(kind) for kind in kinds)


# In plain English: reads one file's text and returns what it uses, as a dictionary of sets, plus the structural problems that need
# no table (a name that is a module used as a value, a handler that does nothing, a return inside finally, a setting with a default).
def facts_of(source, sensitive=()):
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    imported = set()
    local = set()
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.alias):
            imported |= names_bound_by(node)
            parent = parents.get(node)
            if isinstance(parent, ast.Import):
                modules |= names_bound_by(node)
        else:
            local |= names_bound_by(node)
    facts = {key: set() for key in ("imports", "calls", "values", "names", "keywords", "handlers", "shadows", "rebound", "environment", "header_dicts", "sites")}
    kinds = set()
    structure = []
    counts = {}
    for node in ast.walk(tree):
        kinds.add(type(node).__name__)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            facts["imports"] |= import_texts(node)
        elif isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            facts["calls"].add(callee)
            if callee in sensitive:
                counts[f"{callee} in {_function_name(node, parents)}"] = counts.get(f"{callee} in {_function_name(node, parents)}", 0) + 1
            for keyword in node.keywords:
                facts["keywords"].add(keyword.arg or "**")
                if keyword.arg == "headers" and isinstance(keyword.value, ast.Dict):
                    facts["header_dicts"].add("headers={...}")  # a written-out set of headers: only listed files may build one
            if any(isinstance(argument, ast.Starred) for argument in node.args):
                facts["keywords"].add("*")
            if callee in SETTING_READERS and (len(node.args) != 1 or node.keywords):
                structure.append((node.lineno, "reads a setting with a default value or extra arguments (a missing setting must stop the service)"))
        elif isinstance(node, ast.Attribute):
            holder = parents.get(node)
            inner = isinstance(holder, ast.Attribute) and holder.value is node
            called = isinstance(holder, ast.Call) and holder.func is node
            if not inner and not called:
                facts["values"].add(ast.unparse(node))
                if ast.unparse(node) in ("os.environ", "os.environb"):
                    # The whole environment (where passwords live) may only be handed, alone, to a listed settings function.
                    receiver = ast.unparse(holder.func) if isinstance(holder, ast.Call) and holder.args == [node] and not holder.keywords else "<anything else>"
                    facts["environment"].add(receiver)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            holder = parents.get(node)
            if node.id in modules and node.id not in local:
                if not (isinstance(holder, ast.Attribute) and holder.value is node):
                    structure.append((node.lineno, f"uses the module '{node.id}' as a value, not through one of its attributes"))
            elif node.id not in local and node.id not in imported:
                facts["names"].add(node.id)
        elif isinstance(node, ast.ExceptHandler):
            facts["handlers"].add(f"{_function_name(node, parents)}: {', '.join(_caught(node))}")
            if all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body):
                structure.append((node.lineno, "an error handler that does nothing with the error"))
        elif isinstance(node, ast.Try):
            for statement in node.finalbody:
                if not (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)):
                    structure.append((statement.lineno, "a 'finally' block may only make calls (a return, break or continue there swallows errors)"))
    facts["sites"] = {f"{site} x{count}" for site, count in counts.items()}
    facts["shadows"] = {name for name in local if name in BUILTIN_NAMES}
    facts["rebound"] = imported & local
    facts["kinds"] = kinds
    return facts, sorted(structure)


def _label(key):
    return {"values": "attribute", "sites": "call site"}.get(key, key[:-1])


# In plain English: the one question the guardrail asks of a file: what does it use that its allowed entry does not list, and what
# does its entry list that it does not use? Returns two lists of plain sentences, "extra" and "stale".
def compare(source, filename, table):
    entry = table.get(filename.rsplit("/", 1)[-1])
    if entry is None:
        return [f"{filename}: this file is not in the allowed table (tests/allowed_table.py)"], []
    facts, structure = facts_of(source, table["<all files>"]["sensitive_calls"])
    extra = [f"{filename}:{line}: {text}" for line, text in structure]
    stale = []
    for key in ("imports", "calls", "values", "names", "keywords", "handlers", "sites"):
        for item in sorted(facts[key] - set(entry.get(key, ()))):
            extra.append(f"{filename}: uses {_label(key)} '{item}', which is not in its allowed list")
        for item in sorted(set(entry.get(key, ())) - facts[key]):
            stale.append(f"{filename}: allows {_label(key)} '{item}', which it no longer uses")
    everywhere = table["<all files>"]
    for receiver in sorted(facts["environment"] - set(everywhere["environment_receivers"])):
        extra.append(f"{filename}: uses the whole environment other than as the only argument of {sorted(everywhere['environment_receivers'])} ('{receiver}')")
    if facts["header_dicts"] and filename.rsplit("/", 1)[-1] not in everywhere["header_literal_files"]:
        extra.append(f"{filename}: builds a set of headers by hand, which only {sorted(everywhere['header_literal_files'])} may do")
    for name in sorted(facts["shadows"]):
        extra.append(f"{filename}: re-uses the built-in name '{name}' for something else")
    for name in sorted(facts["rebound"]):
        extra.append(f"{filename}: re-binds the imported name '{name}'")
    for kind in sorted(facts["kinds"] - set(table["<all files>"]["kinds"])):
        extra.append(f"{filename}: uses the kind of code '{kind}', which no file is allowed to use")
    return extra, stale
