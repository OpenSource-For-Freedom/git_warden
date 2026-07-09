// A malware scanner (like git_warden itself) enumerating the patterns it detects.
// These are RULE NAMES and descriptions, not an executed payload.
const RULES = [
  'staged_eval_decode',       // eval(atob(...)) (explicit payload staging)
  'env_exfil',                // os.environ reads tainted into a network write (urllib/requests POST)
];

module.exports = { RULES };
