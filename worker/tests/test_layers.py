import pytest

from app.processors.layers import (
    extract_layers,
    parse_size,
    total_size,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("0B", 0),
        ("512B", 512),
        ("77.8MB", 77_800_000),
        ("1.2GB", 1_200_000_000),
        ("245kB", 245_000),
    ],
)
def test_parse_size(value: str, expected: int) -> None:
    assert parse_size(value) == expected


def test_parse_size_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_size("about 3 gigs")


def test_layers_are_reversed_to_dockerfile_order() -> None:
    history = [
        {"CreatedBy": 'CMD ["python"]', "Size": "0B"},
        {"CreatedBy": "/bin/sh -c apt-get install -y curl", "Size": "45MB"},
        {"CreatedBy": "#(nop) FROM debian:11", "Size": "120MB"},
    ]

    layers = extract_layers(history)

    assert layers[0].command == "FROM debian:11"
    assert layers[0].index == 0
    assert layers[2].command.startswith("CMD")


def test_empty_layers_flagged() -> None:
    history = [{"CreatedBy": "#(nop) ENV PATH=/usr/bin", "Size": "0B"}]

    layers = extract_layers(history)

    assert layers[0].is_empty is True


def test_total_size() -> None:
    history = [
        {"CreatedBy": "a", "Size": "10MB"},
        {"CreatedBy": "b", "Size": "5MB"},
    ]

    assert total_size(extract_layers(history)) == 15_000_000
