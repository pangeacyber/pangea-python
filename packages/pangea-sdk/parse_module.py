from __future__ import annotations

import inspect
import json
import logging
import re
import types
import typing as t
from inspect import _empty

import docstring_parser

logger = logging.Logger(__file__)

OID_REGEX = re.compile("OperationId:\s+(.*)")


def _format_annotation(annotation, base_module=None):
    if getattr(annotation, "__module__", None) == "typing":
        return repr(annotation).replace("typing.", "")
    if isinstance(annotation, types.GenericAlias):
        return str(annotation)
    if isinstance(annotation, type):
        if annotation.__module__ in ("builtins", base_module):
            return annotation.__qualname__
        return annotation.__module__ + "." + annotation.__qualname__
    return repr(annotation)


def _merge_with_type_annotations(function, function_section: dict):
    signature = inspect.signature(function)

    for parameter in signature.parameters.values():
        pname = parameter._name  # type: ignore
        if pname in ("self", "cls"):
            continue

        if pname not in function_section["parameters"]:
            logger.warning(
                f"In function {function.__qualname__}: "
                f"Parameter '{pname}' found in function signature, but not in docstring"
            )
            continue

        section = function_section["parameters"][pname]

        annotation = parameter._annotation  # type: ignore
        if annotation is _empty:
            continue

        # This means the doc string for this parameter exists, and is annotated in the actual code
        ptype = _format_annotation(annotation)

        if section["type"] is None:
            logger.warning(
                f"In function {function.__qualname__}: "
                f"Parameter '{pname}' has no type in docstring, but has an annotation"
                f"Will be using its annotation type: {ptype}"
            )
            section["type"] = ptype

        if section["type"] != ptype:
            logger.warning(
                f"In function {function.__qualname__}: "
                f"Parameter '{pname}' has different type in docstring compared to annotation: "
                f"'{section['type']}' vs '{ptype}'"
            )


"""
Commenting this out because:
1) the function isn't actually used
2) it uses python 3.10 syntax which doesn't currently work in our gitlab pipeline
   at this moment, only 3.8 is supported
"""
# def _parse_long_description(description: str | None) -> tuple[str | None, t.List[str]]:
#     if description is None:
#         return description, []

#     start_examples = description.find("```")
#     if start_examples == -1:
#         return description, []

#     desc = description[:start_examples]
#     raw_examples = description[start_examples:]

#     examples = []
#     while start_idx := raw_examples.find("```") != -1:
#         raw_examples = raw_examples[start_idx+3:]
#         end_idx = raw_examples.find("```")
#         if end_idx == -1:
#             logger.warning(f"Found unterminated code snippet section: {description}")
#             break
#         examples.append(raw_examples[:end_idx])
#         raw_examples = raw_examples[end_idx+3:]

#     return desc, examples


def _parse_operation_id(docstring):
    """
    Takes the raw docstring and searches for an OperationId

    Returns the OperationId if found, or None
    """
    match = OID_REGEX.search(docstring)

    if match:
        return match.group(1)

    return None


def _parse_description(description):
    """
    Takes the long description and returns only the description part.

    This is because we've added our own custom OperationId doc tag,
    so we need to grab the description without the OperationId tag.
    """
    if description:
        return description.split("OperationId")[0]

    return None


def _parse_function(function, function_cache=set()) -> t.Optional[dict]:
    if function in function_cache:
        return None

    doc = function.__doc__ or ""
    parsed_doc = docstring_parser.parse(doc)
    ret = {
        "name": function.__name__,
        "summary": parsed_doc.short_description,
        "description": _parse_description(parsed_doc.long_description),
        "examples": [ex.description for ex in parsed_doc.examples],
        "parameters": [],
        "returns": None,
        # "raises": parsed_fn.raises
    }

    parsed_operation_id = _parse_operation_id(doc)
    if parsed_operation_id:
        ret["operation_id"] = parsed_operation_id

    for parameter in parsed_doc.params:
        ret["parameters"].append(
            {
                "name": parameter.arg_name,
                "type": parameter.type_name,
                "optional": parameter.is_optional,
                "description": parameter.description,
            }
        )

    returns = parsed_doc.returns
    if returns:
        ret["returns"] = {
            "name": returns.return_name,
            "type": returns.type_name,
            "description": returns.description,
        }

    _merge_with_type_annotations(function, ret)

    return ret


def _parse_class(klass: type, class_cache=set()) -> t.Optional[dict]:
    if klass in class_cache:
        return None

    doc = klass.__doc__ or ""
    parsed_doc = docstring_parser.parse(doc)
    ret: dict[str, t.Any] = {
        "name": klass.__name__,
        "summary": parsed_doc.short_description,
        "description": parsed_doc.long_description,
        "examples": [ex.description for ex in parsed_doc.examples],
        "functions": [],
    }

    allowed_private = ("__init__", "__call__")

    for fn in dir(klass):
        if fn.startswith("_") and fn not in allowed_private:
            continue

        fn_obj = getattr(klass, fn)
        if not isinstance(fn_obj, types.FunctionType):
            continue

        parsed = _parse_function(fn_obj)
        if parsed:
            ret["functions"].append(parsed)

    return ret


def _parse_module(module: types.ModuleType, module_cache=set()) -> dict:
    if module in module_cache:
        raise Exception("Why are we parsing the same module twice?")

    this_module: dict[str, t.Any] = {}

    # TODO: Maybe require doc string to be present?
    doc = module.__doc__ or ""
    parsed_doc = docstring_parser.parse(doc)
    this_module["module"] = module.__name__
    this_module["summary"] = parsed_doc.short_description
    this_module["description"] = parsed_doc.long_description
    this_module["examples"] = [ex.description for ex in parsed_doc.examples]
    this_module["functions"] = []
    this_module["classes"] = []
    this_module["constants"] = []
    this_module["variables"] = []

    for item in dir(module):
        if item.startswith("_"):
            continue
        obj = getattr(module, item)

        if isinstance(obj, types.ModuleType):
            continue  # Don't parse sub modules

        # Supposedly, this check doesn't work for c python functions
        #  that should be okay though
        elif isinstance(obj, types.FunctionType):
            parsed = _parse_function(obj)
            if parsed:
                this_module["functions"].append(parsed)

        # This check will fail for metaclasses -- let's cross that
        #  bridge when we get there, though
        elif isinstance(obj, type):
            parsed = _parse_class(obj)
            if parsed:
                this_module["classes"].append(parsed)

        # Assume constants either str or int
        elif isinstance(obj, (str, int)):
            this_module["constants"].append(
                {
                    "name": item,
                }
            )

    return this_module


def parse_and_flatten_authn():
    """
    Because AuthN is made up of nested classes, we want to flatten
    everything so we just have a nice list of ALL the functions in AuthN
    """
    import pangea.services

    authn_docs = {
        "functions": [],
    }

    # manually parse authn docs for now because we don't
    # know how else to parse nested classes nicely
    authn_classes = [
        ["authn.session", _parse_module(pangea.services.AuthN.Session)],
        ["authn.client", _parse_module(pangea.services.AuthN.Client)],
        ["authn.client.session", _parse_module(pangea.services.AuthN.Client.Session)],
        ["authn.client.password", _parse_module(pangea.services.AuthN.Client.Password)],
        ["authn.client.token_endpoints", _parse_module(pangea.services.AuthN.Client.Token)],
        ["authn.user", _parse_module(pangea.services.AuthN.User)],
        ["authn.user.profile", _parse_module(pangea.services.AuthN.User.Profile)],
        ["authn.user.authenticators", _parse_module(pangea.services.AuthN.User.Authenticators)],
        ["authn.user.invites", _parse_module(pangea.services.AuthN.User.Invites)],
        ["authn.flow", _parse_module(pangea.services.AuthN.Flow)],
        ["authn.agreements", _parse_module(pangea.services.AuthN.Agreements)],
    ]

    for authn_class in authn_classes:
        for func in authn_class[1]["functions"]:
            doc = {
                **func,
            }

            doc["long_name"] = f"{authn_class[0]}.{func.get('name')}"

            authn_docs["functions"].append(doc)

    return authn_docs


def parse_pangea():
    import pangea
    import pangea.services

    docs = {}
    docs[pangea.__name__] = _parse_module(pangea)
    docs[pangea.services.__name__] = _parse_module(pangea.services)
    docs["AuthN"] = parse_and_flatten_authn()

    return docs


if __name__ == "__main__":
    docs = parse_pangea()
    print(json.dumps(docs))
