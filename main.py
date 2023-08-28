import asyncio
import logging

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, fields
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.policy_decl import AcceptAllAlgorithms
from pyhanko import stamp

logging.basicConfig(
    # level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
)


async def main():
    from rssp import load_rssp

    options = load_rssp()
    chain = options["chain"]
    signer = options["signer"]

    print("\n\n" + "=" * 20 + " RUN " + "=" * 20 + "\n\n")

    with open("input.pdf", "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(
                sig_field_name='MobileIdVnExample',
                box=(200, 600, 400, 660),
            ),
        )
    
        validation_context = ValidationContext(
            allow_fetching=False,
            trust_roots=[chain[-1]],
            other_certs=chain,
            algorithm_usage_policy=AcceptAllAlgorithms(),
        )

        meta = signers.PdfSignatureMetadata(
            field_name="MobileIdVnExample",
            subfilter=SigSeedSubFilter.PADES,
            validation_context=validation_context,
            embed_validation_info=False,
            use_pades_lta=False,
        )
        with open("output.pdf", "wb") as outf:
            pdf_signer = signers.PdfSigner(
                meta,
                signer,
                timestamper=None,
                new_field_spec=None,
                stamp_style=stamp.StaticStampStyle.from_pdf_file('stamp.pdf', border_width=0),
            )
            await pdf_signer.async_sign_pdf(
                w,
                existing_fields_only=False,
                bytes_reserved=None,
                in_place=False,
                output=outf,
            )
     

        print("\n\n============ VALIDATION ============")
        with open("output.pdf", "rb") as outf:
            r = PdfFileReader(outf)
            sig: EmbeddedPdfSignature = r.embedded_signatures[0]

            print("VALIDATION DIGEST:", sig.compute_digest())
            status = await async_validate_pdf_signature(
                sig,
                validation_context,
            )

            print(status.pretty_print_details())


asyncio.run(main())
