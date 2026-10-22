"""The image demo's pixel work: fitting views, and what ECB and CBC leave visible."""

from __future__ import annotations

import os

import pytest
from PIL import Image

from gui.image_demo import MAX_ENCRYPTED_SIDE, encrypt_views, fit_within
from modules.aes_modes import BLOCK_SIZE


def _blocks(image: Image.Image) -> list[bytes]:
    data = image.tobytes()
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _two_colour_image(size: tuple[int, int]) -> Image.Image:
    """Left half red, right half blue: large areas of one colour."""
    image = Image.new("RGB", size, "red")
    image.paste("blue", (size[0] // 2, 0, size[0], size[1]))
    return image


@pytest.mark.parametrize(
    ("size", "fitted"),
    [
        ((200, 200), (150, 150)),
        ((40, 2000), (3, 150)),  # tall: the height decides
        ((2000, 40), (150, 3)),  # wide: the width decides
        ((10, 5), (150, 75)),  # small images are enlarged
        ((1, 100_000), (1, 150)),  # never thinner than a pixel
    ],
)
def test_fit_within_keeps_proportions_inside_the_square(
    size: tuple[int, int], fitted: tuple[int, int]
) -> None:
    assert fit_within(size, 150) == fitted


def test_ecb_repeats_blocks_where_cbc_does_not() -> None:
    views = encrypt_views(_two_colour_image((96, 64)), os.urandom(16))

    ecb, cbc = _blocks(views.ecb), _blocks(views.cbc)
    # One colour repeats every 48 bytes (3 × 16), so ECB has a handful of
    # distinct blocks; CBC chains every block into the next.
    assert len(set(ecb)) <= 8
    assert len(set(cbc)) == len(cbc)


def test_a_large_image_is_shrunk_without_mixing_colours() -> None:
    views = encrypt_views(_two_colour_image((2000, 1000)), os.urandom(16))

    assert views.shrunk
    assert views.source_size == (2000, 1000)
    assert views.original.size == (MAX_ENCRYPTED_SIDE, MAX_ENCRYPTED_SIDE // 2)
    assert views.ecb.size == views.cbc.size == views.original.size
    # Nearest-neighbour sampling: still exactly two colours, no blended ones.
    colours = views.original.getcolors()
    assert colours is not None  # None would mean more than 256 colours
    assert {colour for _, colour in colours} == {(255, 0, 0), (0, 0, 255)}


def test_a_small_image_is_encrypted_as_it_is() -> None:
    image = _two_colour_image((64, 48))

    views = encrypt_views(image, os.urandom(16))

    assert not views.shrunk
    assert views.original.tobytes() == image.tobytes()


def test_other_image_modes_are_converted_to_rgb() -> None:
    palette = _two_colour_image((32, 32)).convert("P")

    views = encrypt_views(palette, os.urandom(16))

    assert views.original.mode == views.ecb.mode == views.cbc.mode == "RGB"
