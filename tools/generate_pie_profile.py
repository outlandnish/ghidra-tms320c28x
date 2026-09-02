#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nishanth Samala
"""Generate a PIE vector-identity profile from a TI C2000Ware device header.

The PIE vector table is the highest-value naming surface in a stripped C28x
image: a handler's slot names the peripheral that raises it, which is usually
the fastest route into an unknown subsystem. The slot order is a hardware fact,
and TI publishes it as the member order of `struct PIE_VECT_TABLE` in
`<device>_pievect.h`. This script turns that declaration order into a JSON
profile the analysis scripts can read, so no slot table is hand-transcribed.

Usage:
    tools/generate_pie_profile.py <device>_pievect.h -o data/device_profiles/<name>.json

The header is TI-licensed (BSD-3-Clause) and is NOT redistributed here -- point
this script at your own C2000Ware install. The generated profile carries the
identifiers and their one-line descriptions, which stay TI-derived; see
data/device_profiles/README.md and THIRD-PARTY.md.
"""
import argparse
import hashlib
import json
import re
import sys

# `    PINT  ADCA1_INT;    // 1.1 - ADCA Interrupt 1`
MEMBER = re.compile(r"^\s*PINT\s+(\w+)\s*;\s*(?://\s*(.*?)\s*)?$")


def parse_vectors(text):
    """Members of `struct PIE_VECT_TABLE`, in declaration order.

    Declaration order IS slot order -- the struct is overlaid on the vector
    table at its base address, and every member is one PINT. Reading the order
    rather than any address in the header is what keeps this correct for parts
    whose table base differs.
    """
    start = text.find("struct PIE_VECT_TABLE")
    if start < 0:
        raise SystemExit("no `struct PIE_VECT_TABLE` in this header")
    body = text[text.index("{", start) + 1:]
    end = body.find("};")
    if end < 0:
        raise SystemExit("unterminated `struct PIE_VECT_TABLE`")

    vectors = []
    for line in body[:end].splitlines():
        match = MEMBER.match(line)
        if match:
            vectors.append({
                "slot": len(vectors),
                "name": match.group(1),
                "description": (match.group(2) or "").strip(),
            })
    if not vectors:
        raise SystemExit("struct parsed but no PINT members matched")
    return vectors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("header", help="path to <device>_pievect.h")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--profile-name", default=None,
                        help="defaults to the header's device prefix")
    args = parser.parse_args()

    raw = open(args.header, "rb").read()
    vectors = parse_vectors(raw.decode("utf-8", "replace"))
    name = args.profile_name or re.sub(r"_pievect\.h$", "",
                                       args.header.replace("\\", "/").split("/")[-1],
                                       flags=re.IGNORECASE)

    profile = {
        "schema": "c28x-pie-profile/1",
        "profileName": name,
        "provenance": {
            "generatedBy": "tools/generate_pie_profile.py",
            "sourceHeader": args.header.replace("\\", "/").split("/")[-1],
            "sourceSha256": hashlib.sha256(raw).hexdigest(),
            "license": "TI C2000Ware device header, BSD-3-Clause (see NOTICE)",
        },
        "vectorCount": len(vectors),
        "vectors": vectors,
    }
    with open(args.output, "w", encoding="utf-8", newline="\n") as out:
        json.dump(profile, out, indent=2)
        out.write("\n")
    print(f"wrote {args.output}: {len(vectors)} vectors from {name}", file=sys.stderr)


if __name__ == "__main__":
    main()
