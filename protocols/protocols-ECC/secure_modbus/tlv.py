from __future__ import annotations

from dataclasses import dataclass

from .frame import ProtocolError


@dataclass
class DataMessage:
    system_id_bitmask: int
    values: dict[int, bytes]
    requests: list[int]


def encode_data_message(
    values: dict[int, bytes] | None = None,
    requests: list[int] | None = None,
    system_id_bitmask: int = 1,
) -> bytes:
    values = values or {}
    requests = requests or []
    out = bytearray([system_id_bitmask & 0xFF, len(values) & 0xFF])
    for datatype_id, value in values.items():
        if len(value) > 0xFFFF:
            raise ValueError(f"datatype {datatype_id} exceeds 65535 bytes")
        out.append(datatype_id & 0xFF)
        out.extend(len(value).to_bytes(2, "big"))
        out.extend(value)
    out.append(len(requests) & 0xFF)
    out.extend(x & 0xFF for x in requests)
    return bytes(out)


def decode_data_message(data: bytes) -> DataMessage:
    if len(data) < 3:
        raise ProtocolError("data APDU body is too short")
    pos = 0
    system_id_bitmask = data[pos]
    pos += 1
    value_count = data[pos]
    pos += 1
    values: dict[int, bytes] = {}
    for _ in range(value_count):
        if pos + 3 > len(data):
            raise ProtocolError("truncated datatype header")
        datatype_id = data[pos]
        length = int.from_bytes(data[pos + 1 : pos + 3], "big")
        pos += 3
        if pos + length > len(data):
            raise ProtocolError("truncated datatype value")
        values[datatype_id] = data[pos : pos + length]
        pos += length
    if pos >= len(data):
        raise ProtocolError("missing request datatype count")
    request_count = data[pos]
    pos += 1
    if pos + request_count != len(data):
        raise ProtocolError("request datatype list length mismatch")
    return DataMessage(system_id_bitmask, values, list(data[pos:]))
