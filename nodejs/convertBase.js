/**
 * Converts a number of any size between arbitrary bases.
 * You can pass either a numeric base (e.g. 16) or a custom character set string.
 *
 * @param {string} inputStr - The input number string.
 * @param {string|number} inputCharset - Input base number or charset string.
 * @param {string|number} outputCharset - Output base number or charset string.
 * @returns {string} The converted number string in the target base/charset.
 */
export function convertBase(inputStr, inputCharset, outputCharset) {
  if (typeof inputStr !== "string" || !inputStr.length)
    throw new Error("Input string must be non-empty.");

  // --- helper: get charset from base or string ---
  function getCharset(baseOrSet) {
    if (typeof baseOrSet === "number") {
      const standard =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      if (baseOrSet < 2 || baseOrSet > standard.length)
        throw new Error(
          `Numeric base must be between 2 and ${standard.length} (got ${baseOrSet}).`
        );
      return standard.slice(0, baseOrSet);
    }
    if (typeof baseOrSet === "string") {
      if (baseOrSet.length < 2)
        throw new Error("Charset string must have at least 2 characters.");
      return baseOrSet;
    }
    throw new Error("Base/charset must be a number or string.");
  }

  const inSet = getCharset(inputCharset);
  const outSet = getCharset(outputCharset);
  const inBase = BigInt(inSet.length);
  const outBase = BigInt(outSet.length);

  // --- Step 1: Convert input string → BigInt ---
  let value = 0n;
  for (const ch of inputStr) {
    const digit = inSet.indexOf(ch);
    if (digit === -1)
      throw new Error(`Invalid character '${ch}' for input base/charset.`);
    value = value * inBase + BigInt(digit);
  }

  // --- Step 2: Convert BigInt → output base string ---
  if (value === 0n) return outSet[0];

  let result = "";
  while (value > 0n) {
    const remainder = value % outBase;
    result = outSet[Number(remainder)] + result;
    value /= outBase;
  }

  return result;
}
