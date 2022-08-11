from pathlib import Path
from sys import stdout

from lxml import etree

from signxml.exceptions import InvalidSignature
from signxml import XMLSigner
from signxml import XMLVerifier
from signxml import methods as sign_methods

import typer


class Error(Exception):
    """Generic error for this task"""


def main(
    cert_path: Path,
    key_path: Path,
    mdfile_path: Path,
    output_path: Path = None,
):
    # load creds
    with open(cert_path) as fd:
        cert = fd.read()
    with open(key_path) as fd:
        key = fd.read()

    # parse xml
    tree = etree.parse(mdfile_path)
    root = tree.getroot()

    # cleanup pre-existing signatures
    for node in root.iterchildren():
        if node.tag == "{http://www.w3.org/2000/09/xmldsig#}Signature":
            root.remove(node)

    # signature placeholder
    node_signature_placeholder = etree.Element(
        "{http://www.w3.org/2000/09/xmldsig#}Signature",
        Id="placeholder",
        nsmap=root.nsmap,
    )
    root.insert(0, node_signature_placeholder)

    # sign
    signer = XMLSigner(method=sign_methods.enveloped)
    signer.namespaces = root.nsmap
    root_signed = signer.sign(root, key=key, cert=cert, reference_uri=root.attrib.get("ID"))

    # verify signed data
    verifier = XMLVerifier()
    try:
        verified_data = verifier.verify(
            root_signed,
            require_x509=True,
            x509_cert=cert,
            validate_schema=True,
        ).signed_xml
    except InvalidSignature as e:
        error_context = {
            "message": "Failed to verify signature for document",
            "document": etree.tostring(root).decode("utf-8"),
            "document_signed": etree.tostring(root_signed).decode("utf-8"),
            "error": str(e),
        }
        raise Error(error_context) from e

    if verified_data is None:
        error_context = {
            "message": "No verified data found",
            "doc": etree.tostring(root).decode("utf-8"),
            "doc_signed": etree.tostring(root_signed).decode("utf-8"),
            "verified_data": etree.tostring(verified_data).decode("utf-8"),
        }
        raise Error(error_context)

    # serialize
    output_data = etree.tostring(root_signed, xml_declaration=True, encoding="utf-8")
    if output_path:
        output_path.write_bytes(output_data)
    else:
        stdout.buffer.write(output_data)


def cli():
    typer.run(main)


if __name__ == "__main__":
    typer.run(main)
