// check if running in node or browser
const webcrypto: SubtleCrypto = window === undefined ? require('crypto').webcrypto.subtle : window.crypto.subtle

export default webcrypto
