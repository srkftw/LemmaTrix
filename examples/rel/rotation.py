# SPDX-License-Identifier: CC0-1.0
# Original local source fixture for authorized source-first reconstruction.
ROTATION = 5


def transform_byte(value: int) -> int:
    if 97 <= value <= 122:
        return (value - 97 + ROTATION) % 26 + 97
    return value
