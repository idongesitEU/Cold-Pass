/**
 * Converts a string in base `b` to binary (no Number/parseInt limits),
 * performs n rounds of pairwise XOR (non-overlapping),
 * and returns the result as a string in base `b`.
 *
 * Works for extremely large numbers (BigInt-safe).
 */
export function xorTransform(inputStr, base, n = 1) {
  if (base < 2 || base > 36)
    throw new Error("Base must be between 2 and 36.");
  if (!Number.isInteger(n) || n < 0)
    throw new Error("n must be a non-negative integer.");
  if (!inputStr || typeof inputStr !== "string")
    throw new Error("inputStr must be a non-empty string.");

  // --- Step 1: Normalize input ---
  let str = inputStr.trim().toLowerCase();
  if (str.startsWith("0x")) str = str.slice(2);

  // --- Step 2: Convert to BigInt safely ---
  let numBig;
  if (base === 10) {
    numBig = BigInt(str);
  } else if (base === 16) {
    numBig = BigInt("0x" + str);
  } else {
    const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz".slice(0, base);
    numBig = 0n;
    for (let ch of str) {
      const val = alphabet.indexOf(ch);
      if (val === -1) throw new Error(`Invalid digit '${ch}' for base ${base}`);
      numBig = numBig * BigInt(base) + BigInt(val);
    }
  }

  // --- Step 3: Convert BigInt → binary array ---
  let bits = numBig.toString(2).split("").map(b => (b === "1" ? 1 : 0));

  // --- Step 4: Perform XOR rounds on non-overlapping pairs ---
  for (let round = 0; round < n; round++) {
    const next = [];
    for (let i = 0; i < bits.length; i += 2) {
      if (i + 1 < bits.length) {
        next.push(bits[i] ^ bits[i + 1]);
      } else {
        next.push(bits[i]); // carry last bit if unpaired
      }
    }
    bits = next;
    if (bits.length <= 1) break;
  }

  // --- Step 5: Convert binary array → BigInt ---
  const binStr = bits.join("") || "0";
  const resultBig = BigInt("0b" + binStr);

  // --- Step 6: Convert BigInt → base-b string ---
  function bigIntToBase(big, base) {
    if (big === 0n) return "0";
    const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz".slice(0, base);
    let result = "";
    let temp = big < 0n ? -big : big;
    while (temp > 0n) {
      result = alphabet[temp % BigInt(base)] + result;
      temp = temp / BigInt(base);
    }
    return result;
  }

  return bigIntToBase(resultBig, base);
}
