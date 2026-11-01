// Regenerate with Node when updating Unicode data; no network or hand-kept list.
import { writeFileSync } from 'node:fs';
const invisible = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}\p{Co}\p{Default_Ignorable_Code_Point}\u2800]|[^\S ]/u;
const ranges = [];
for (let cp = 0; cp <= 0x10FFFF; cp++) {
  if (!invisible.test(String.fromCodePoint(cp))) continue;
  const previous = ranges.at(-1);
  if (previous && previous[1] === cp - 1) previous[1] = cp;
  else ranges.push([cp, cp]);
}
writeFileSync(new URL('Unicode-Safety.json', import.meta.url), JSON.stringify({ unicodeVersion: process.versions.unicode, ranges }, null, 2) + '\n');
