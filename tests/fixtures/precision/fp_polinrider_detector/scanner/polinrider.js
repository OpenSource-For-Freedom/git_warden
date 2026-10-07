// Detects PolinRider loader markers in a checkout.
const MARKERS = ["rmcej%otb%", "Cot%3t=shtP", "global['_V']='8-st"];
module.exports = (text) => MARKERS.some((m) => text.includes(m));
