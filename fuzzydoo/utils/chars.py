
CHAR_RANGES = {
    'ascii': [(0x00, 0x7f)],
    'utf8': [(0x0000, 0xd7ff), (0xe000, 0x10ffff)],
    'utf_16_be': [(0x0000, 0xd7ff), (0xe000, 0x10ffff)],
    'utf_32_be': [(0x0000, 0xd7ff), (0xe000, 0x10ffff)],
    'iso2022_jp_2004': [(0x00, 0x7e), (0x3040, 0x309f), (0x30a0, 0x30ff), (0x4e00, 0x9fff)]
}
"""A dictionary mapping the name of a character encoding to a list of minimum and maximum integer 
values allowed for that encoding.

Example:
    >>> CHAR_RANGES['ascii']
    [(0x00, 0x7f)]
"""

TOTAL_CHARS = {
    'ascii': sum(end - start + 1 for start, end in CHAR_RANGES['ascii']),
    'utf8': sum(end - start + 1 for start, end in CHAR_RANGES['utf8']),
    'utf_16_be': sum(end - start + 1 for start, end in CHAR_RANGES['utf_16_be']),
    'utf_32_be': sum(end - start + 1 for start, end in CHAR_RANGES['utf_32_be']),
    'iso2022_jp_2004': sum(end - start + 1 for start, end in CHAR_RANGES['iso2022_jp_2004'])
}
"""A dictionary mapping the name of a character encoding to the total number of allowed values for 
that encoding.

Example:
    >>> TOTAL_CHARS['ascii']
    128
"""
