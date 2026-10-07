// Zero-width code points: variation selectors do not take up a column.
export function isZeroWidth(str, i) {
  const cp = str.codePointAt(i);
  return (cp >= 0xFE00 && cp <= 0xFE0F) || (cp >= 0xE0100 && cp <= 0xE01EF);
}
