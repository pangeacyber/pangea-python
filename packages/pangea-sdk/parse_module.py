from __future__ import annotations

import inspect
import json
import logging
import re
import types
from dataclasses import dataclass, field, replace
from inspect import _empty

import docstring_parser

logger = logging.Logger(__file__)

OID_REGEX = re.compile(r"OperationId:\s+(.*)$", re.MULTILINE)


@dataclass()
class Parameter:
    name: str
    description: str | None = None
    type: str | None = None
    optional: bool | None = None

    @staticmethod
    def from_docstring(doc: docstring_parser.DocstringParam) -> Parameter:
        return Parameter(name=doc.arg_name, description=doc.description, type=doc.type_name, optional=doc.is_optional)


@dataclass()
class Returns:
    name: str | None = None
    description: str | None = None
    type: str | None = None

    @staticmethod
    def from_docstring(doc: docstring_parser.DocstringReturns) -> Returns:
        return Returns(name=doc.return_name, description=doc.description, type=doc.type_name)


@dataclass()
class Function:
    name: str
    examples: list[str]
    description: str | None = None
    long_name: str | None = None
    operation_id: str | None = None
    parameters: list[Parameter] = field(default_factory=list)
    returns: Returns | None = None
    summary: str | None = None


@dataclass()
class Constant:
    name: str


@dataclass()
class Class:
    name: str
    description: str | None = None
    examples: list[str] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    summary: str | None = None


@dataclass()
class DocumentationModule:
    classes: list[Class] = field(default_factory=list)
    constants: list[Constant] = field(default_factory=list)
    description: str | None = None
    examples: list[str] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    module: str | None = None
    summary: str | None = None
    variables: list[Function] = field(default_factory=list)


def _format_annotation(annotation: object, base_module: str | None = None) -> str:
    if isinstance(annotation, str):
        return annotation
    if getattr(annotation, "__module__", None) == "typing":
        return repr(annotation).replace("typing.", "")
    if isinstance(annotation, types.GenericAlias):  # type: ignore[attr-defined]
        return str(annotation)
    if isinstance(annotation, type):
        if annotation.__module__ in ("builtins", base_module):
            return annotation.__qualname__
        return annotation.__module__ + "." + annotation.__qualname__
    return repr(annotation)


def _merge_with_type_annotations(function, function_section: Function) -> None:
    signature = inspect.signature(function)

    for parameter in signature.parameters.values():
        pname = parameter._name  # type: ignore[attr-defined]
        if pname in ("self", "cls"):
            continue

        if pname not in [x.name for x in function_section.parameters]:
            logger.warning(
                f"In function {function.__qualname__}: "
                f"parameter '{pname}' found in function signature, but not in docstring."
            )
            continue

        annotation = parameter._annotation  # type: ignore[attr-defined]
        if annotation is _empty:
            continue

        # This means the doc string for this parameter exists, and is annotated in the actual code
        ptype = _format_annotation(annotation)
        section = next(x for x in function_section.parameters if x.name == pname)

        # This is no longer worth warning about, it is fine for the types to not
        # be in the docstring because we pull that from the real type annotation
        # anyways.
        # if section.type is None:
        #     logger.warning(
        #         f"In function {function.__qualname__}: "
        #         f"Parameter '{pname}' has no type in docstring, but has an annotation. "
        #         f"Will be using its annotation type: {ptype}"
        #     )
        #     section.type = ptype

        # This is finnicky because of how the types are qualified. For example,
        # this warns on differences like 'm.AgreementType' vs 'pangea.services.authn.models.AgreementType'
        # and 'bool' vs 'Optional[bool]', which can be considered valid but
        # ultimately it would be better to just stick to using the type
        # annotations over the docstring annotations.
        # if section.type != ptype:
        #     logger.warning(
        #         f"In function {function.__qualname__}: "
        #         f"Parameter '{pname}' has different type in docstring compared to annotation: "
        #         f"'{section.type}' vs '{ptype}'"
        #     )

        if parameter._default is _empty and section.optional:  # type: ignore[attr-defined]
            logger.warning(
                f"In function {function.__qualname__}: "
                f"Parameter '{pname}' is documented as optional but is actually required."
            )

        section.optional = parameter._default is not _empty  # type: ignore[attr-defined]


"""
Commenting this out because:
1) the function isn't actually used
2) it uses python 3.10 syntax which doesn't currently work in our gitlab pipeline
   at this moment, only 3.7 is supported
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


def _parse_operation_id(docstring: str) -> str | None:
    """
    Takes the raw docstring and searches for an OperationId

    Returns the OperationId if found, or None
    """
    match = OID_REGEX.search(docstring)

    if match:
        return match.group(1)

    return None


def _parse_description(description: str | None = None) -> str | None:
    """
    Takes the long description and returns only the description part.

    This is because we've added our own custom OperationId doc tag,
    so we need to grab the description without the OperationId tag.
    """
    if description:
        return description.split("OperationId")[0]

    return None


def _parse_function(function: types.FunctionType) -> Function | None:
    doc = function.__doc__ or ""
    parsed_doc = docstring_parser.parse(doc)
    ret = Function(
        name=function.__name__,
        summary=parsed_doc.short_description,
        description=_parse_description(parsed_doc.long_description),
        examples=[ex.description for ex in parsed_doc.examples if ex.description],
        parameters=[Parameter.from_docstring(x) for x in parsed_doc.params],
        returns=Returns.from_docstring(parsed_doc.returns) if parsed_doc.returns else None,
        # "raises"=parsed_fn.raises
    )

    # If there was no docstring to begin with, there is no point in any further
    # processing.
    if len(doc) == 0:
        return ret

    # Otherwise look for operation ID and type annotations.

    parsed_operation_id = _parse_operation_id(doc)
    if parsed_operation_id:
        ret.operation_id = parsed_operation_id

    _merge_with_type_annotations(function, ret)

    return ret


def _parse_class(klass: type) -> Class | None:
    doc = klass.__doc__ or ""
    parsed_doc = docstring_parser.parse(doc)
    ret = Class(
        name=klass.__name__,
        summary=parsed_doc.short_description,
        description=parsed_doc.long_description,
        examples=[ex.description for ex in parsed_doc.examples if ex.description],
        functions=[],
    )

    allowed_private = ("__init__", "__call__")

    for fn in dir(klass):
        if fn.startswith("_") and fn not in allowed_private:
            continue

        fn_obj = getattr(klass, fn)
        if not isinstance(fn_obj, types.FunctionType):
            continue

        parsed = _parse_function(fn_obj)
        if parsed:
            ret.functions.append(parsed)

    return ret


def _parse_module(module: types.ModuleType | types.FunctionType | type) -> DocumentationModule:
    # TODO: Maybe require doc string to be present?
    doc = module.__doc__ or ""
    parsed_doc = docstring_parser.parse(doc)
    this_module = DocumentationModule(
        module=module.__name__,
        summary=parsed_doc.short_description,
        description=parsed_doc.long_description,
        examples=[ex.description for ex in parsed_doc.examples if ex.description],
    )

    for item in dir(module):
        if item.startswith("_"):
            continue
        obj = getattr(module, item)

        if isinstance(obj, types.ModuleType):
            continue  # Don't parse sub modules

        # Supposedly, this check doesn't work for c python functions
        #  that should be okay though
        elif isinstance(obj, types.FunctionType):
            parsed_func = _parse_function(obj)
            if parsed_func:
                this_module.functions.append(parsed_func)

        # This check will fail for metaclasses -- let's cross that
        #  bridge when we get there, though
        elif isinstance(obj, type):
            parsed_class = _parse_class(obj)
            if parsed_class:
                this_module.classes.append(parsed_class)

        # Assume constants either str or int
        elif isinstance(obj, (str, int)):
            this_module.constants.append(Constant(name=item))

    return this_module


def parse_and_flatten_authn() -> DocumentationModule:
    """
    Because AuthN is made up of nested classes, we want to flatten
    everything so we just have a nice list of ALL the functions in AuthN
    """
    import pangea.services

    authn_docs = DocumentationModule()

    # manually parse authn docs for now because we don't
    # know how else to parse nested classes nicely
    authn_classes: list[tuple[str, DocumentationModule]] = [
        ("authn.session", _parse_module(pangea.services.AuthN.Session)),
        ("authn.client", _parse_module(pangea.services.AuthN.Client)),
        ("authn.client.session", _parse_module(pangea.services.AuthN.Client.Session)),
        ("authn.client.password", _parse_module(pangea.services.AuthN.Client.Password)),
        ("authn.client.token_endpoints", _parse_module(pangea.services.AuthN.Client.Token)),
        ("authn.user", _parse_module(pangea.services.AuthN.User)),
        ("authn.user.profile", _parse_module(pangea.services.AuthN.User.Profile)),
        ("authn.user.authenticators", _parse_module(pangea.services.AuthN.User.Authenticators)),
        ("authn.user.invites", _parse_module(pangea.services.AuthN.User.Invites)),
        ("authn.flow", _parse_module(pangea.services.AuthN.Flow)),
        ("authn.agreements", _parse_module(pangea.services.AuthN.Agreements)),
    ]

    for authn_class in authn_classes:
        for func in authn_class[1].functions:
            doc = replace(func, long_name=f"{authn_class[0]}.{func.name}")
            authn_docs.functions.append(doc)

    return authn_docs


def parse_pangea() -> dict[str, DocumentationModule]:
    import pangea
    import pangea.services

    docs: dict[str, DocumentationModule] = {}
    docs[pangea.__name__] = _parse_module(pangea)
    docs[pangea.services.__name__] = _parse_module(pangea.services)
    docs["AuthN"] = parse_and_flatten_authn()

    return docs


if __name__ == "__main__":
    docs = parse_pangea()
    print(json.dumps(docs, default=lambda o: o.__dict__, indent=2))
