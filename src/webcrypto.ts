// check if running in node or browser

const isBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';
const webcrypto: SubtleCrypto = isBrowser ? window.crypto.subtle : require('crypto').webcrypto.subtle

export default webcrypto
