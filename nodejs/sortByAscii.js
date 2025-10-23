/**
 * Sort an array by ASCII order of each item's string representation.
 * Returns a new sorted array (original array is not mutated).
 *
 * @param {Array} arr - input array (items may be strings, numbers, symbols, etc.)
 * @returns {Array} - new array sorted according to ASCII character codes
 */
export function sortByAscii(arr) {
  // Defensive copy so we don't mutate the original
  return arr.slice().sort((a, b) => compareAscii(String(a), String(b)));
}

/**
 * Compare two strings by ASCII (code unit) values, lexicographically.
 * Returns negative if s < t, positive if s > t, zero if equal.
 *
 * Note: uses JS charCodeAt (UTF-16 code units). For ASCII characters
 * (0-127) this is identical to ASCII ordering.
 */
function compareAscii(s, t) {
  const len = Math.min(s.length, t.length);
  for (let i = 0; i < len; i++) {
    const diff = s.charCodeAt(i) - t.charCodeAt(i);
    if (diff !== 0) return diff;
  }
  // If one is prefix of the other, shorter string comes first
  return s.length - t.length;
}
