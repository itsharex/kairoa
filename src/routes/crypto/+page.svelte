<script lang="ts">
  import { translationsStore } from '$lib/stores/i18n';
  import { Check, Copy } from 'lucide-svelte';
  import { page } from '$app/stores';
  import CryptoJS from 'crypto-js';
  
  type CryptoType = 'rsa' | 'asymmetric' | 'symmetric';
  
  let cryptoType = $state<CryptoType>('rsa');
  
  // Check URL parameter for type
  $effect(() => {
    const typeParam = $page.url.searchParams.get('type');
    if (typeParam === 'rsa') {
      cryptoType = 'rsa';
    } else if (typeParam === 'asymmetric') {
      cryptoType = 'asymmetric';
    } else if (typeParam === 'symmetric') {
      cryptoType = 'symmetric';
    }
  });
  
  // RSA specific state
  type KeySize = 1024 | 2048 | 3072 | 4096;
  type KeyFormat = 'pem' | 'der';
  
  let keySize = $state<KeySize>(2048);
  let keyFormat = $state<KeyFormat>('pem');
  let publicKey = $state('');
  let privateKey = $state('');
  let isGenerating = $state(false);
  let publicKeyCopied = $state(false);
  let privateKeyCopied = $state(false);
  
  // Symmetric algorithm state
  type SymmetricAlgorithm = 'AES' | 'DES' | '3DES' | 'Rabbit' | 'RC2' | 'RC4';
  type BlockCipherMode = 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR' | 'GCM';
  let symmetricAlgorithm = $state<SymmetricAlgorithm>('AES');
  let aesMode = $state<BlockCipherMode>('GCM'); // Mode for AES
  let desMode = $state<BlockCipherMode>('CBC'); // Mode for DES
  let tripleDesMode = $state<BlockCipherMode>('CBC'); // Mode for 3DES
  let rc2Mode = $state<BlockCipherMode>('CBC'); // Mode for RC2
  let symmetricKey = $state('');
  let symmetricInput = $state('');
  let symmetricOutput = $state('');
  let symmetricIv = $state('');
  let isEncrypting = $state(true);
  let symmetricCopied = $state(false);
  let symmetricError = $state('');
  
  // Asymmetric algorithm state
  type AsymmetricAlgorithm = 'RSA-OAEP' | 'RSA-PSS' | 'ECDSA' | 'ECDH' | 'DSA';
  type AsymmetricOperation = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'keyExchange';
  type NamedCurve = 'P-256' | 'P-384' | 'P-521';
  let asymmetricAlgorithm = $state<AsymmetricAlgorithm>('RSA-OAEP');
  let asymmetricOperation = $state<AsymmetricOperation>('encrypt');
  let namedCurve = $state<NamedCurve>('P-256'); // For ECDSA and ECDH
  let asymmetricPublicKey = $state('');
  let asymmetricPrivateKey = $state('');
  let asymmetricPeerPublicKey = $state(''); // For ECDH key exchange
  let asymmetricInput = $state('');
  let asymmetricOutput = $state('');
  let asymmetricError = $state('');
  let asymmetricCopied = $state(false);

  let translations = $derived($translationsStore);

  function t(key: string): string {
    const keys = key.split('.');
    let value: any = translations;
    for (const k of keys) {
      value = value?.[k];
    }
    return value || key;
  }

  function switchCryptoType(type: CryptoType) {
    cryptoType = type;
    // Reset RSA state
    if (type === 'rsa') {
      publicKey = '';
      privateKey = '';
      publicKeyCopied = false;
      privateKeyCopied = false;
    }
    // Reset asymmetric state
    if (type === 'asymmetric') {
      asymmetricPublicKey = '';
      asymmetricPrivateKey = '';
      asymmetricPeerPublicKey = '';
      asymmetricInput = '';
      asymmetricOutput = '';
      asymmetricError = '';
      asymmetricCopied = false;
      asymmetricAlgorithm = 'RSA-OAEP';
      asymmetricOperation = 'encrypt';
      namedCurve = 'P-256';
    }
    // Reset symmetric state
    if (type === 'symmetric') {
      symmetricKey = '';
      symmetricInput = '';
      symmetricOutput = '';
      symmetricIv = '';
      symmetricCopied = false;
      symmetricError = '';
      symmetricAlgorithm = 'AES'; // Reset to default
      aesMode = 'GCM'; // Reset AES mode
      desMode = 'CBC'; // Reset DES mode
      tripleDesMode = 'CBC'; // Reset 3DES mode
      rc2Mode = 'CBC'; // Reset RC2 mode
    }
  }

  // 将 ArrayBuffer 转换为 Base64
  function arrayBufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  // 将 ArrayBuffer 转换为十六进制字符串
  function arrayBufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      const byte = bytes[i];
      hex += (byte < 16 ? '0' : '') + byte.toString(16).toUpperCase();
    }
    return hex;
  }

  // 格式化十六进制字符串（每 32 个字符换行）
  function formatHex(hex: string): string {
    const chunks = [];
    for (let i = 0; i < hex.length; i += 32) {
      chunks.push(hex.slice(i, i + 32));
    }
    return chunks.join('\n');
  }

  // 将 Base64 转换为 PEM 格式
  function base64ToPEM(base64: string, type: 'PUBLIC' | 'PRIVATE'): string {
    const header = type === 'PUBLIC' 
      ? '-----BEGIN PUBLIC KEY-----\n'
      : '-----BEGIN PRIVATE KEY-----\n';
    const footer = type === 'PUBLIC'
      ? '\n-----END PUBLIC KEY-----'
      : '\n-----END PRIVATE KEY-----';
    
    // 每 64 个字符换行
    const chunks = [];
    for (let i = 0; i < base64.length; i += 64) {
      chunks.push(base64.slice(i, i + 64));
    }
    
    return header + chunks.join('\n') + footer;
  }

  // 导出公钥
  async function exportPublicKey(key: CryptoKey, format: KeyFormat): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', key);
    
    if (format === 'pem') {
      const base64 = arrayBufferToBase64(exported);
      return base64ToPEM(base64, 'PUBLIC');
    } else {
      // DER 格式显示为十六进制
      return formatHex(arrayBufferToHex(exported));
    }
  }

  // 导出私钥
  async function exportPrivateKey(key: CryptoKey, format: KeyFormat): Promise<string> {
    const exported = await crypto.subtle.exportKey('pkcs8', key);
    
    if (format === 'pem') {
      const base64 = arrayBufferToBase64(exported);
      return base64ToPEM(base64, 'PRIVATE');
    } else {
      // DER 格式显示为十六进制
      return formatHex(arrayBufferToHex(exported));
    }
  }

  async function generateKeyPair() {
    isGenerating = true;
    publicKey = '';
    privateKey = '';
    publicKeyCopied = false;
    privateKeyCopied = false;

    try {
      // 生成 RSA 密钥对
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: keySize,
          publicExponent: new Uint8Array([1, 0, 1]), // 65537
          hash: 'SHA-256',
        },
        true, // 可导出
        ['encrypt', 'decrypt']
      );

      // 导出密钥对
      publicKey = await exportPublicKey(keyPair.publicKey, keyFormat);
      privateKey = await exportPrivateKey(keyPair.privateKey, keyFormat);
    } catch (error) {
      console.error('Error generating key pair:', error);
      publicKey = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
      privateKey = '';
    } finally {
      isGenerating = false;
    }
  }

  async function copyToClipboard(text: string, type: 'public' | 'private') {
    try {
      await navigator.clipboard.writeText(text);
      if (type === 'public') {
        publicKeyCopied = true;
        setTimeout(() => {
          publicKeyCopied = false;
        }, 2000);
      } else {
        privateKeyCopied = true;
        setTimeout(() => {
          privateKeyCopied = false;
        }, 2000);
      }
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }

  function clearRSA() {
    publicKey = '';
    privateKey = '';
    publicKeyCopied = false;
    privateKeyCopied = false;
  }
  
  // PEM to ArrayBuffer (extract base64 content)
  function pemToArrayBuffer(pem: string): ArrayBuffer {
    // Remove PEM headers/footers and whitespace
    const base64 = pem
      .replace(/-----BEGIN (PUBLIC|PRIVATE) KEY-----/g, '')
      .replace(/-----END (PUBLIC|PRIVATE) KEY-----/g, '')
      .replace(/\s/g, '');
    
    // Convert base64 to binary
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  // Import RSA public key from PEM
  async function importRSAPublicKey(pem: string): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      false,
      ['encrypt']
    );
  }
  
  // Import RSA private key from PEM
  async function importRSAPrivateKey(pem: string): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      false,
      ['decrypt']
    );
  }
  
  // Import RSA public key for signing (RSA-PSS)
  async function importRSAPublicKeyForSigning(pem: string): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      false,
      ['verify']
    );
  }
  
  // Import RSA private key for signing (RSA-PSS)
  async function importRSAPrivateKeyForSigning(pem: string): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSA-PSS',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );
  }
  
  // RSA-OAEP Encrypt
  async function encryptRSAOAEP() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPublicKey.trim()) {
      asymmetricError = t('crypto.asymmetric.publicKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.inputRequired');
      return;
    }
    
    try {
      const publicKey = await importRSAPublicKey(asymmetricPublicKey);
      const inputBuffer = new TextEncoder().encode(asymmetricInput);
      
      // RSA-OAEP has a maximum message size based on key size
      // For 2048-bit key, max is 190 bytes (256 - 2*32 - 2)
      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'RSA-OAEP',
        },
        publicKey,
        inputBuffer
      );
      
      asymmetricOutput = arrayBufferToBase64(encrypted);
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // RSA-OAEP Decrypt
  async function decryptRSAOAEP() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPrivateKey.trim()) {
      asymmetricError = t('crypto.asymmetric.privateKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.inputRequired');
      return;
    }
    
    try {
      const privateKey = await importRSAPrivateKey(asymmetricPrivateKey);
      const encryptedBuffer = base64ToArrayBuffer(asymmetricInput);
      
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'RSA-OAEP',
        },
        privateKey,
        encryptedBuffer
      );
      
      asymmetricOutput = new TextDecoder().decode(decrypted);
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Invalid encrypted data or key'}`;
    }
  }
  
  // RSA-PSS Sign
  async function signRSAPSS() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPrivateKey.trim()) {
      asymmetricError = t('crypto.asymmetric.privateKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.inputRequired');
      return;
    }
    
    try {
      const privateKey = await importRSAPrivateKeyForSigning(asymmetricPrivateKey);
      const inputBuffer = new TextEncoder().encode(asymmetricInput);
      
      const signature = await crypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength: 32,
        },
        privateKey,
        inputBuffer
      );
      
      asymmetricOutput = arrayBufferToBase64(signature);
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // RSA-PSS Verify
  async function verifyRSAPSS() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPublicKey.trim()) {
      asymmetricError = t('crypto.asymmetric.publicKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.inputRequired');
      return;
    }
    
    // For verification, input should be the original message
    // We need to split message and signature, or use a different approach
    // For now, let's assume the user provides message and signature separately
    // We'll use a simple format: message|signature
    try {
      const publicKey = await importRSAPublicKeyForSigning(asymmetricPublicKey);
      
      // Try to parse as message|signature format
      const parts = asymmetricInput.split('|');
      if (parts.length !== 2) {
        asymmetricError = t('crypto.asymmetric.invalidFormat');
        return;
      }
      
      const message = parts[0];
      const signatureBase64 = parts[1];
      
      const messageBuffer = new TextEncoder().encode(message);
      const signatureBuffer = base64ToArrayBuffer(signatureBase64);
      
      const isValid = await crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: 32,
        },
        publicKey,
        signatureBuffer,
        messageBuffer
      );
      
      asymmetricOutput = isValid ? t('crypto.asymmetric.verificationSuccess') : t('crypto.asymmetric.verificationFailed');
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Invalid signature or key'}`;
    }
  }
  
  // Import ECDSA public key from PEM
  async function importECDSAPublicKey(pem: string, curve: NamedCurve): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: curve,
      },
      false,
      ['verify']
    );
  }
  
  // Import ECDSA private key from PEM
  async function importECDSAPrivateKey(pem: string, curve: NamedCurve): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: curve,
      },
      false,
      ['sign']
    );
  }
  
  // ECDSA Sign
  async function signECDSA() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPrivateKey.trim()) {
      asymmetricError = t('crypto.asymmetric.privateKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.inputRequired');
      return;
    }
    
    try {
      const privateKey = await importECDSAPrivateKey(asymmetricPrivateKey, namedCurve);
      const inputBuffer = new TextEncoder().encode(asymmetricInput);
      
      const signature = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: 'SHA-256',
        },
        privateKey,
        inputBuffer
      );
      
      asymmetricOutput = arrayBufferToBase64(signature);
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // ECDSA Verify
  async function verifyECDSA() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPublicKey.trim()) {
      asymmetricError = t('crypto.asymmetric.publicKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.inputRequired');
      return;
    }
    
    try {
      const publicKey = await importECDSAPublicKey(asymmetricPublicKey, namedCurve);
      
      // Parse message|signature format
      const parts = asymmetricInput.split('|');
      if (parts.length !== 2) {
        asymmetricError = t('crypto.asymmetric.invalidFormat');
        return;
      }
      
      const message = parts[0];
      const signatureBase64 = parts[1];
      
      const messageBuffer = new TextEncoder().encode(message);
      const signatureBuffer = base64ToArrayBuffer(signatureBase64);
      
      const isValid = await crypto.subtle.verify(
        {
          name: 'ECDSA',
          hash: 'SHA-256',
        },
        publicKey,
        signatureBuffer,
        messageBuffer
      );
      
      asymmetricOutput = isValid ? t('crypto.asymmetric.verificationSuccess') : t('crypto.asymmetric.verificationFailed');
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Invalid signature or key'}`;
    }
  }
  
  // Import ECDH public key from PEM
  async function importECDHPublicKey(pem: string, curve: NamedCurve): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'spki',
      keyData,
      {
        name: 'ECDH',
        namedCurve: curve,
      },
      false,
      []
    );
  }
  
  // Import ECDH private key from PEM
  async function importECDHPrivateKey(pem: string, curve: NamedCurve): Promise<CryptoKey> {
    const keyData = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'ECDH',
        namedCurve: curve,
      },
      false,
      ['deriveBits', 'deriveKey']
    );
  }
  
  // ECDH Key Exchange
  async function exchangeECDH() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!asymmetricPrivateKey.trim()) {
      asymmetricError = t('crypto.asymmetric.privateKeyRequired');
      return;
    }
    
    if (!asymmetricPeerPublicKey.trim()) {
      asymmetricError = t('crypto.asymmetric.peerPublicKeyRequired');
      return;
    }
    
    try {
      const privateKey = await importECDHPrivateKey(asymmetricPrivateKey, namedCurve);
      const peerPublicKey = await importECDHPublicKey(asymmetricPeerPublicKey, namedCurve);
      
      // Derive shared secret (256 bits = 32 bytes)
      const sharedSecret = await crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: peerPublicKey,
        },
        privateKey,
        256 // 256 bits = 32 bytes
      );
      
      // Convert to Base64 for display
      asymmetricOutput = arrayBufferToBase64(sharedSecret);
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // Execute asymmetric operation
  async function executeAsymmetricOperation() {
    if (asymmetricAlgorithm === 'RSA-OAEP') {
      if (asymmetricOperation === 'encrypt') {
        await encryptRSAOAEP();
      } else if (asymmetricOperation === 'decrypt') {
        await decryptRSAOAEP();
      }
    } else if (asymmetricAlgorithm === 'RSA-PSS') {
      if (asymmetricOperation === 'sign') {
        await signRSAPSS();
      } else if (asymmetricOperation === 'verify') {
        await verifyRSAPSS();
      }
    } else if (asymmetricAlgorithm === 'ECDSA') {
      if (asymmetricOperation === 'sign') {
        await signECDSA();
      } else if (asymmetricOperation === 'verify') {
        await verifyECDSA();
      }
    } else if (asymmetricAlgorithm === 'ECDH') {
      if (asymmetricOperation === 'keyExchange') {
        await exchangeECDH();
      }
    } else if (asymmetricAlgorithm === 'DSA') {
      asymmetricError = t('crypto.asymmetric.dsaNotSupported');
    }
  }
  
  // Copy asymmetric output to clipboard
  async function copyAsymmetricToClipboard() {
    try {
      await navigator.clipboard.writeText(asymmetricOutput);
      asymmetricCopied = true;
      setTimeout(() => {
        asymmetricCopied = false;
      }, 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }
  
  // Clear asymmetric data
  function clearAsymmetric() {
    asymmetricPublicKey = '';
    asymmetricPrivateKey = '';
    asymmetricPeerPublicKey = '';
    asymmetricInput = '';
    asymmetricOutput = '';
    asymmetricError = '';
    asymmetricCopied = false;
  }
  
  // Text to ArrayBuffer (UTF-8 encoding)
  function textToArrayBuffer(text: string): ArrayBuffer {
    return new TextEncoder().encode(text).buffer;
  }
  
  // Hex string to ArrayBuffer
  function hexToArrayBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes.buffer;
  }
  
  // Check if string is valid hex
  function isValidHex(str: string): boolean {
    return /^[0-9A-Fa-f]+$/.test(str) && str.length % 2 === 0;
  }
  
  // Base64 to ArrayBuffer (kept for encrypted data input/output)
  function base64ToArrayBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
  
  // Import key from text
  async function importSymmetricKey(keyText: string, algorithmName: string): Promise<CryptoKey> {
    const keyBuffer = textToArrayBuffer(keyText);
    return await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: algorithmName },
      false,
      ['encrypt', 'decrypt']
    );
  }
  
  // Check if algorithm requires IV
  function requiresIV(algorithm: SymmetricAlgorithm): boolean {
    // ECB mode doesn't use IV, RC4 is a stream cipher without IV
    if (algorithm === 'RC4') {
      return false;
    }
    // AES depends on selected mode
    if (algorithm === 'AES') {
      return aesMode !== 'ECB';
    }
    // DES, 3DES, and RC2 depend on selected mode
    if (algorithm === 'DES') {
      return desMode !== 'ECB';
    }
    if (algorithm === '3DES') {
      return tripleDesMode !== 'ECB';
    }
    if (algorithm === 'RC2') {
      return rc2Mode !== 'ECB';
    }
    // Rabbit always requires IV (8 bytes)
    return true;
  }
  
  // Get IV length for algorithm
  function getIVLength(algorithm: SymmetricAlgorithm): number {
    if (algorithm === 'AES') {
      switch (aesMode) {
        case 'GCM':
          return 12;
        case 'CBC':
        case 'CTR':
        case 'CFB':
        case 'OFB':
          return 16;
        case 'ECB':
          return 0;
        default:
          return 16;
      }
    }
    switch (algorithm) {
      case 'DES':
      case '3DES':
      case 'RC2':
        return 8;
      case 'Rabbit':
        return 8;
      case 'RC4':
        return 0;
      default:
        return 16;
    }
  }
  
  // Check if algorithm uses Web Crypto API
  // Web Crypto API only supports AES-GCM, AES-CBC, AES-CTR
  function usesWebCryptoAPI(algorithm: SymmetricAlgorithm): boolean {
    return algorithm === 'AES' && (aesMode === 'GCM' || aesMode === 'CBC' || aesMode === 'CTR');
  }
  
  // Get AES algorithm name for Web Crypto API
  function getAESAlgorithmName(): string {
    return `AES-${aesMode}`;
  }
  
  // Get valid key lengths for algorithm
  function getValidKeyLengths(algorithm: SymmetricAlgorithm): number[] {
    switch (algorithm) {
      case 'AES':
        return [16, 24, 32];
      case 'DES':
        return [8];
      case '3DES':
        return [16, 24];
      case 'Rabbit':
        return [16];
      case 'RC2':
        return []; // Variable length 1-128 bytes
      case 'RC4':
        return []; // Variable length 1-256 bytes
      default:
        return [];
    }
  }
  
  // Get key length description for algorithm
  function getKeyLengthDescription(algorithm: SymmetricAlgorithm): string {
    const validLengths = getValidKeyLengths(algorithm);
    const algorithmName = getAlgorithmDisplayName();
    
    if (validLengths.length > 0) {
      const lengthDescriptions = validLengths.map(len => {
        const bits = len * 8;
        return `${len} bytes (${bits} bits)`;
      });
      return `${algorithmName}: ${lengthDescriptions.join(', ')}`;
    }
    
    switch (algorithm) {
      case 'RC2':
        return `${algorithmName}: 1-128 bytes (8-1024 bits)`;
      case 'RC4':
        return `${algorithmName}: 1-256 bytes (8-2048 bits)`;
      default:
        return '';
    }
  }
  
  // Get algorithm and mode display name
  function getAlgorithmDisplayName(): string {
    switch (symmetricAlgorithm) {
      case 'AES':
        return `AES-${aesMode}`;
      case 'DES':
        return `DES-${desMode}`;
      case '3DES':
        return `3DES-${tripleDesMode}`;
      case 'RC2':
        return `RC2-${rc2Mode}`;
      case 'Rabbit':
        return 'Rabbit';
      case 'RC4':
        return 'RC4';
      default:
        return symmetricAlgorithm;
    }
  }
  
  // Encrypt with symmetric algorithm
  async function encryptSymmetric() {
    symmetricError = '';
    symmetricOutput = '';
    
    if (!symmetricKey.trim()) {
      symmetricError = t('crypto.symmetric.keyRequired');
      return;
    }
    
    if (!symmetricInput.trim()) {
      symmetricError = isEncrypting ? t('crypto.symmetric.plaintextRequired') : t('crypto.symmetric.ciphertextRequired');
      return;
    }
    
    try {
      // Use Web Crypto API for AES
      if (usesWebCryptoAPI(symmetricAlgorithm)) {
        const keyBuffer = textToArrayBuffer(symmetricKey);
        const keyLength = keyBuffer.byteLength;
        const validLengths = getValidKeyLengths(symmetricAlgorithm);
        if (!validLengths.includes(keyLength)) {
          const algorithmName = getAlgorithmDisplayName();
          const expectedLengths = getKeyLengthDescription(symmetricAlgorithm);
          symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${expectedLengths})`;
          return;
        }
        
        // Import key with correct algorithm name
        const algorithmName = getAESAlgorithmName();
        const key = await crypto.subtle.importKey(
          'raw',
          keyBuffer,
          { name: algorithmName },
          false,
          ['encrypt', 'decrypt']
        );
        
        const inputBuffer = new TextEncoder().encode(symmetricInput);
        
        // All Web Crypto API AES modes require IV
        let iv: Uint8Array;
        if (symmetricIv.trim()) {
          // Try to parse as hex first, then as text
          const ivText = symmetricIv.trim();
          if (isValidHex(ivText)) {
            iv = new Uint8Array(hexToArrayBuffer(ivText));
          } else {
            iv = new Uint8Array(textToArrayBuffer(ivText));
          }
          const ivLength = iv.byteLength;
          const expectedIvLength = getIVLength(symmetricAlgorithm);
          if (ivLength !== expectedIvLength) {
            symmetricError = t('crypto.symmetric.invalidIvLength') + ` (Current: ${ivLength} bytes, Expected: ${expectedIvLength} bytes)`;
            return;
          }
        } else {
          const ivLength = getIVLength(symmetricAlgorithm);
          iv = crypto.getRandomValues(new Uint8Array(ivLength));
          symmetricIv = arrayBufferToHex(iv.buffer);
        }
        
        const encrypted = await crypto.subtle.encrypt(
          { name: algorithmName, iv: iv },
          key,
          inputBuffer
        );
        
        symmetricOutput = arrayBufferToBase64(encrypted);
      } else {
        // Use crypto-js for other algorithms (DES, 3DES, Rabbit, RC2, RC4, and AES-ECB, AES-CFB, AES-OFB)
        const keyWordArray = CryptoJS.enc.Utf8.parse(symmetricKey);
        const keyLength = keyWordArray.sigBytes;
        
        // Validate key length for different algorithms
        const validKeyLengths = getValidKeyLengths(symmetricAlgorithm);
        
        if (validKeyLengths.length > 0) {
          if (!validKeyLengths.includes(keyLength)) {
            const algorithmName = getAlgorithmDisplayName();
            const expectedLengths = getKeyLengthDescription(symmetricAlgorithm);
            symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${expectedLengths})`;
            return;
          }
        } else {
          // Variable length algorithms (RC2, RC4)
          let minLength = 0;
          let maxLength = 0;
          if (symmetricAlgorithm === 'RC2') {
            minLength = 1;
            maxLength = 128;
          } else if (symmetricAlgorithm === 'RC4') {
            minLength = 1;
            maxLength = 256;
          }
          if (keyLength < minLength || keyLength > maxLength) {
            const algorithmName = getAlgorithmDisplayName();
            symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${minLength}-${maxLength} bytes)`;
            return;
          }
        }
        
        const plaintextWordArray = CryptoJS.enc.Utf8.parse(symmetricInput);
        
        let encrypted: CryptoJS.lib.CipherParams;
        let ivWordArray: CryptoJS.lib.WordArray | undefined;
        
        if (requiresIV(symmetricAlgorithm)) {
          if (symmetricIv.trim()) {
            // Try to parse as hex first, then as text
            const ivText = symmetricIv.trim();
            if (isValidHex(ivText)) {
              const ivBuffer = hexToArrayBuffer(ivText);
              ivWordArray = CryptoJS.lib.WordArray.create(Array.from(new Uint8Array(ivBuffer)));
            } else {
              ivWordArray = CryptoJS.enc.Utf8.parse(ivText);
            }
            const ivLength = ivWordArray.sigBytes;
            const expectedIvLength = getIVLength(symmetricAlgorithm);
            if (ivLength !== expectedIvLength) {
              symmetricError = t('crypto.symmetric.invalidIvLength') + ` (Current: ${ivLength} bytes, Expected: ${expectedIvLength} bytes)`;
              return;
            }
          } else {
            // Generate random IV
            const ivLength = getIVLength(symmetricAlgorithm);
            const ivBytes = crypto.getRandomValues(new Uint8Array(ivLength));
            ivWordArray = CryptoJS.lib.WordArray.create(Array.from(ivBytes));
            symmetricIv = arrayBufferToHex(ivBytes.buffer);
          }
        }
        
        switch (symmetricAlgorithm) {
          case 'AES': {
            const mode = aesMode === 'ECB' ? CryptoJS.mode.ECB :
                         aesMode === 'CBC' ? CryptoJS.mode.CBC :
                         aesMode === 'CFB' ? CryptoJS.mode.CFB :
                         aesMode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            const options: any = {
              mode: mode,
              padding: CryptoJS.pad.Pkcs7
            };
            if (aesMode !== 'ECB' && ivWordArray) {
              options.iv = ivWordArray;
            }
            encrypted = CryptoJS.AES.encrypt(plaintextWordArray, keyWordArray, options);
            break;
          }
          case 'DES': {
            const mode = desMode === 'ECB' ? CryptoJS.mode.ECB :
                         desMode === 'CBC' ? CryptoJS.mode.CBC :
                         desMode === 'CFB' ? CryptoJS.mode.CFB :
                         desMode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            const options: any = {
              mode: mode,
              padding: CryptoJS.pad.Pkcs7
            };
            if (desMode !== 'ECB' && ivWordArray) {
              options.iv = ivWordArray;
            }
            encrypted = CryptoJS.DES.encrypt(plaintextWordArray, keyWordArray, options);
            break;
          }
          case '3DES': {
            const mode = tripleDesMode === 'ECB' ? CryptoJS.mode.ECB :
                         tripleDesMode === 'CBC' ? CryptoJS.mode.CBC :
                         tripleDesMode === 'CFB' ? CryptoJS.mode.CFB :
                         tripleDesMode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            const options: any = {
              mode: mode,
              padding: CryptoJS.pad.Pkcs7
            };
            if (tripleDesMode !== 'ECB' && ivWordArray) {
              options.iv = ivWordArray;
            }
            encrypted = CryptoJS.TripleDES.encrypt(plaintextWordArray, keyWordArray, options);
            break;
          }
          case 'Rabbit':
            encrypted = CryptoJS.Rabbit.encrypt(plaintextWordArray, keyWordArray, {
              iv: ivWordArray
            });
            break;
          case 'RC2': {
            const mode = rc2Mode === 'ECB' ? CryptoJS.mode.ECB :
                         rc2Mode === 'CBC' ? CryptoJS.mode.CBC :
                         rc2Mode === 'CFB' ? CryptoJS.mode.CFB :
                         rc2Mode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            const options: any = {
              mode: mode,
              padding: CryptoJS.pad.Pkcs7
            };
            if (rc2Mode !== 'ECB' && ivWordArray) {
              options.iv = ivWordArray;
            }
            encrypted = CryptoJS.RC2.encrypt(plaintextWordArray, keyWordArray, options);
            break;
          }
          case 'RC4':
            encrypted = CryptoJS.RC4.encrypt(plaintextWordArray, keyWordArray);
            break;
          default:
            throw new Error('Unsupported algorithm');
        }
        
        symmetricOutput = encrypted.toString();
      }
    } catch (error) {
      symmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // Decrypt with symmetric algorithm
  async function decryptSymmetric() {
    symmetricError = '';
    symmetricOutput = '';
    
    if (!symmetricKey.trim()) {
      symmetricError = t('crypto.symmetric.keyRequired');
      return;
    }
    
    if (!symmetricInput.trim()) {
      symmetricError = t('crypto.symmetric.ciphertextRequired');
      return;
    }
    
    if (requiresIV(symmetricAlgorithm) && !symmetricIv.trim()) {
      const expectedIvLength = getIVLength(symmetricAlgorithm);
      symmetricError = t('crypto.symmetric.ivRequired') + ` (Required: ${expectedIvLength} bytes)`;
      return;
    }
    
    try {
      // Use Web Crypto API for AES
      if (usesWebCryptoAPI(symmetricAlgorithm)) {
        const keyBuffer = textToArrayBuffer(symmetricKey);
        const keyLength = keyBuffer.byteLength;
        const validLengths = getValidKeyLengths(symmetricAlgorithm);
        if (!validLengths.includes(keyLength)) {
          const algorithmName = getAlgorithmDisplayName();
          const expectedLengths = getKeyLengthDescription(symmetricAlgorithm);
          symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${expectedLengths})`;
          return;
        }
        
        // Import key with correct algorithm name
        const algorithmName = getAESAlgorithmName();
        const key = await crypto.subtle.importKey(
          'raw',
          keyBuffer,
          { name: algorithmName },
          false,
          ['encrypt', 'decrypt']
        );
        
        const encryptedBuffer = base64ToArrayBuffer(symmetricInput);
        
        // All Web Crypto API AES modes require IV
        if (!symmetricIv.trim()) {
          const expectedIvLength = getIVLength(symmetricAlgorithm);
          symmetricError = t('crypto.symmetric.ivRequired') + ` (Required: ${expectedIvLength} bytes)`;
          return;
        }
        // Try to parse as hex first, then as text
        const ivText = symmetricIv.trim();
        let iv: Uint8Array;
        if (isValidHex(ivText)) {
          iv = new Uint8Array(hexToArrayBuffer(ivText));
        } else {
          iv = new Uint8Array(textToArrayBuffer(ivText));
        }
        const ivLength = iv.byteLength;
        const expectedIvLength = getIVLength(symmetricAlgorithm);
        if (ivLength !== expectedIvLength) {
          symmetricError = t('crypto.symmetric.invalidIvLength') + ` (Current: ${ivLength} bytes, Expected: ${expectedIvLength} bytes)`;
          return;
        }
        
        const decrypted = await crypto.subtle.decrypt(
          { name: algorithmName, iv: iv },
          key,
          encryptedBuffer
        );
        
        symmetricOutput = new TextDecoder().decode(decrypted);
      } else {
        // Use crypto-js for other algorithms (DES, 3DES, Rabbit, RC2, RC4, and AES-ECB, AES-CFB, AES-OFB)
        const keyWordArray = CryptoJS.enc.Utf8.parse(symmetricKey);
        const keyLength = keyWordArray.sigBytes;
        
        // Validate key length for different algorithms
        const validKeyLengths = getValidKeyLengths(symmetricAlgorithm);
        
        if (validKeyLengths.length > 0) {
          if (!validKeyLengths.includes(keyLength)) {
            const algorithmName = getAlgorithmDisplayName();
            const expectedLengths = getKeyLengthDescription(symmetricAlgorithm);
            symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${expectedLengths})`;
            return;
          }
        } else {
          // Variable length algorithms (RC2, RC4)
          let minLength = 0;
          let maxLength = 0;
          if (symmetricAlgorithm === 'RC2') {
            minLength = 1;
            maxLength = 128;
          } else if (symmetricAlgorithm === 'RC4') {
            minLength = 1;
            maxLength = 256;
          }
          if (keyLength < minLength || keyLength > maxLength) {
            const algorithmName = getAlgorithmDisplayName();
            symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${minLength}-${maxLength} bytes)`;
            return;
          }
        }
        
        // crypto-js encrypt returns Base64 string, decrypt accepts Base64 string directly
        const ciphertext = symmetricInput;
        
        let decrypted: CryptoJS.lib.WordArray;
        let options: any = {};
        
        if (requiresIV(symmetricAlgorithm)) {
          // Try to parse as hex first, then as text
          const ivText = symmetricIv.trim();
          let ivWordArray: CryptoJS.lib.WordArray;
          if (isValidHex(ivText)) {
            const ivBuffer = hexToArrayBuffer(ivText);
            ivWordArray = CryptoJS.lib.WordArray.create(Array.from(new Uint8Array(ivBuffer)));
          } else {
            ivWordArray = CryptoJS.enc.Utf8.parse(ivText);
          }
          const ivLength = ivWordArray.sigBytes;
          const expectedIvLength = getIVLength(symmetricAlgorithm);
          if (ivLength !== expectedIvLength) {
            symmetricError = t('crypto.symmetric.invalidIvLength') + ` (Current: ${ivLength} bytes, Expected: ${expectedIvLength} bytes)`;
            return;
          }
          options.iv = ivWordArray;
        }
        
        switch (symmetricAlgorithm) {
          case 'AES': {
            const mode = aesMode === 'ECB' ? CryptoJS.mode.ECB :
                         aesMode === 'CBC' ? CryptoJS.mode.CBC :
                         aesMode === 'CFB' ? CryptoJS.mode.CFB :
                         aesMode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            options.mode = mode;
            options.padding = CryptoJS.pad.Pkcs7;
            decrypted = CryptoJS.AES.decrypt(ciphertext, keyWordArray, options);
            break;
          }
          case 'DES': {
            const mode = desMode === 'ECB' ? CryptoJS.mode.ECB :
                         desMode === 'CBC' ? CryptoJS.mode.CBC :
                         desMode === 'CFB' ? CryptoJS.mode.CFB :
                         desMode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            options.mode = mode;
            options.padding = CryptoJS.pad.Pkcs7;
            decrypted = CryptoJS.DES.decrypt(ciphertext, keyWordArray, options);
            break;
          }
          case '3DES': {
            const mode = tripleDesMode === 'ECB' ? CryptoJS.mode.ECB :
                         tripleDesMode === 'CBC' ? CryptoJS.mode.CBC :
                         tripleDesMode === 'CFB' ? CryptoJS.mode.CFB :
                         tripleDesMode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            options.mode = mode;
            options.padding = CryptoJS.pad.Pkcs7;
            decrypted = CryptoJS.TripleDES.decrypt(ciphertext, keyWordArray, options);
            break;
          }
          case 'Rabbit':
            decrypted = CryptoJS.Rabbit.decrypt(ciphertext, keyWordArray, options);
            break;
          case 'RC2': {
            const mode = rc2Mode === 'ECB' ? CryptoJS.mode.ECB :
                         rc2Mode === 'CBC' ? CryptoJS.mode.CBC :
                         rc2Mode === 'CFB' ? CryptoJS.mode.CFB :
                         rc2Mode === 'OFB' ? CryptoJS.mode.OFB :
                         CryptoJS.mode.CBC;
            options.mode = mode;
            options.padding = CryptoJS.pad.Pkcs7;
            decrypted = CryptoJS.RC2.decrypt(ciphertext, keyWordArray, options);
            break;
          }
          case 'RC4':
            decrypted = CryptoJS.RC4.decrypt(ciphertext, keyWordArray);
            break;
          default:
            throw new Error('Unsupported algorithm');
        }
        
        symmetricOutput = decrypted.toString(CryptoJS.enc.Utf8);
      }
    } catch (error) {
      symmetricError = `Error: ${error instanceof Error ? error.message : 'Invalid encrypted data or key'}`;
    }
  }
  
  // Generate random key
  function generateSymmetricKey() {
    const keyLength = 32; // 256 bits
    const key = crypto.getRandomValues(new Uint8Array(keyLength));
    symmetricKey = arrayBufferToBase64(key.buffer);
  }
  
  async function copySymmetricToClipboard() {
    if (!symmetricOutput) return;
    
    try {
      await navigator.clipboard.writeText(symmetricOutput);
      symmetricCopied = true;
      setTimeout(() => {
        symmetricCopied = false;
      }, 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }
  
  function clearSymmetric() {
    symmetricKey = '';
    symmetricInput = '';
    symmetricOutput = '';
    symmetricIv = '';
    symmetricCopied = false;
    symmetricError = '';
  }
</script>

<div class="flex flex-col h-full w-full ml-0 mr-0 p-2">
  <!-- 输入区域卡片 -->
  <div class="card flex-1 flex flex-col">
    <div class="flex-1 flex flex-col space-y-4">
      <!-- 加解密类型切换 -->
      <div class="border-b border-gray-200 dark:border-gray-700">
        <div class="flex gap-6">
          <button
            onclick={() => switchCryptoType('rsa')}
            class="px-4 py-2 relative transition-colors font-medium {cryptoType === 'rsa'
              ? 'text-primary-600 dark:text-primary-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}"
          >
            {t('rsa.title')}
            {#if cryptoType === 'rsa'}
              <span class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary-600 dark:text-primary-400"></span>
            {/if}
          </button>
          <button
            onclick={() => switchCryptoType('asymmetric')}
            class="px-4 py-2 relative transition-colors font-medium {cryptoType === 'asymmetric'
              ? 'text-primary-600 dark:text-primary-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}"
          >
            {t('crypto.asymmetric.title')}
            {#if cryptoType === 'asymmetric'}
              <span class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary-600 dark:text-primary-400"></span>
            {/if}
          </button>
          <button
            onclick={() => switchCryptoType('symmetric')}
            class="px-4 py-2 relative transition-colors font-medium {cryptoType === 'symmetric'
              ? 'text-primary-600 dark:text-primary-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}"
          >
            {t('crypto.symmetric.title')}
            {#if cryptoType === 'symmetric'}
              <span class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary-600 dark:text-primary-400"></span>
            {/if}
          </button>
        </div>
      </div>

      <!-- RSA Key Pair Generator -->
      {#if cryptoType === 'rsa'}
        <div class="flex-1 flex flex-col space-y-6 min-h-0 overflow-y-auto">
          <!-- 配置区域 -->
          <div class="flex-shrink-0">
            <div class="space-y-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label for="key-size" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('rsa.keySize')}
                  </label>
                  <select
                    id="key-size"
                    bind:value={keySize}
                    class="input w-full"
                  >
                    <option value={1024}>1024 bits</option>
                    <option value={2048}>2048 bits</option>
                    <option value={3072}>3072 bits</option>
                    <option value={4096}>4096 bits</option>
                  </select>
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {t('rsa.keySizeDescription')}
                  </p>
                </div>

                <div>
                  <label for="key-format" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('rsa.keyFormat')}
                  </label>
                  <select
                    id="key-format"
                    bind:value={keyFormat}
                    class="input w-full"
                  >
                    <option value="pem">PEM</option>
                    <option value="der">DER (Hex)</option>
                  </select>
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {t('rsa.keyFormatDescription')}
                  </p>
                </div>
              </div>

              <div class="flex gap-2">
                <button
                  onclick={generateKeyPair}
                  disabled={isGenerating}
                  class="px-4 py-2 text-white rounded-lg transition-colors font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
                  style="background-color: #818089;"
                >
                  {#if isGenerating}
                    {t('rsa.generating')}
                  {:else}
                    {t('rsa.generate')}
                  {/if}
                </button>
                <button
                  onclick={clearRSA}
                  disabled={isGenerating}
                  class="btn-secondary"
                >
                  {t('rsa.clear')}
                </button>
              </div>
            </div>
          </div>

          <!-- 公钥卡片 -->
          {#if publicKey}
            <div class="flex-shrink-0">
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {t('rsa.publicKey')}
                  </h3>
                  <button
                    onclick={() => copyToClipboard(publicKey, 'public')}
                    class="btn-secondary whitespace-nowrap transition-all duration-200 {publicKeyCopied ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
                  >
                    {#if publicKeyCopied}
                      <span class="flex items-center gap-1">
                        <Check class="w-4 h-4" />
                        {t('common.copied')}
                      </span>
                    {:else}
                      <span class="flex items-center gap-1">
                        <Copy class="w-4 h-4" />
                        {t('common.copy')}
                      </span>
                    {/if}
                  </button>
                </div>

                <textarea
                  value={publicKey}
                  readonly
                  class="textarea font-mono text-sm min-h-[120px] {publicKeyCopied ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
                ></textarea>
              </div>
            </div>
          {/if}

          <!-- 私钥卡片 -->
          {#if privateKey}
            <div class="flex-shrink-0">
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {t('rsa.privateKey')}
                  </h3>
                  <button
                    onclick={() => copyToClipboard(privateKey, 'private')}
                    class="btn-secondary whitespace-nowrap transition-all duration-200 {privateKeyCopied ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
                  >
                    {#if privateKeyCopied}
                      <span class="flex items-center gap-1">
                        <Check class="w-4 h-4" />
                        {t('common.copied')}
                      </span>
                    {:else}
                      <span class="flex items-center gap-1">
                        <Copy class="w-4 h-4" />
                        {t('common.copy')}
                      </span>
                    {/if}
                  </button>
                </div>

                <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3 mb-2">
                  <p class="text-sm text-yellow-800 dark:text-yellow-200">
                    <strong>{t('rsa.warning')}</strong> {t('rsa.warningDescription')}
                  </p>
                </div>

                <textarea
                  value={privateKey}
                  readonly
                  class="textarea font-mono text-sm min-h-[200px] {privateKeyCopied ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
                ></textarea>
              </div>
            </div>
          {/if}
          </div>
      {:else if cryptoType === 'asymmetric'}
        <!-- Asymmetric Algorithm -->
        <div class="flex-1 flex flex-col space-y-4 min-h-0 overflow-y-auto">
          <!-- Algorithm selection -->
          <div class="flex-shrink-0">
            <label for="asymmetric-algorithm" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
              {t('crypto.asymmetric.algorithm')}
            </label>
            <select
              id="asymmetric-algorithm"
              bind:value={asymmetricAlgorithm}
              class="input w-full"
            >
              <option value="RSA-OAEP">RSA-OAEP (Encryption/Decryption)</option>
              <option value="RSA-PSS">RSA-PSS (Sign/Verify)</option>
              <option value="ECDSA">ECDSA (Sign/Verify)</option>
              <option value="ECDH">ECDH (Key Exchange)</option>
              <option value="DSA">DSA (Not Supported)</option>
            </select>
          </div>

          <!-- Curve selection for ECDSA and ECDH -->
          {#if asymmetricAlgorithm === 'ECDSA' || asymmetricAlgorithm === 'ECDH'}
            <div class="flex-shrink-0">
              <label for="named-curve" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.asymmetric.namedCurve')}
              </label>
              <select
                id="named-curve"
                bind:value={namedCurve}
                class="input w-full"
              >
                <option value="P-256">P-256 (secp256r1)</option>
                <option value="P-384">P-384 (secp384r1)</option>
                <option value="P-521">P-521 (secp521r1)</option>
              </select>
            </div>
          {/if}

          <!-- Operation selection -->
          <div class="flex-shrink-0">
            <label for="asymmetric-operation" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
              {t('crypto.asymmetric.operation')}
            </label>
            <select
              id="asymmetric-operation"
              bind:value={asymmetricOperation}
              class="input w-full"
            >
              {#if asymmetricAlgorithm === 'RSA-OAEP'}
                <option value="encrypt">{t('crypto.asymmetric.encrypt')}</option>
                <option value="decrypt">{t('crypto.asymmetric.decrypt')}</option>
              {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA'}
                <option value="sign">{t('crypto.asymmetric.sign')}</option>
                <option value="verify">{t('crypto.asymmetric.verify')}</option>
              {:else if asymmetricAlgorithm === 'ECDH'}
                <option value="keyExchange">{t('crypto.asymmetric.keyExchange')}</option>
              {:else if asymmetricAlgorithm === 'DSA'}
                <option value="sign" disabled>{t('crypto.asymmetric.sign')}</option>
                <option value="verify" disabled>{t('crypto.asymmetric.verify')}</option>
              {/if}
            </select>
          </div>

          <!-- Key inputs -->
          <div class="flex-shrink-0 grid grid-cols-2 gap-4">
            {#if asymmetricAlgorithm === 'RSA-OAEP'}
              {#if asymmetricOperation === 'encrypt'}
                <!-- Public key for encryption -->
                <div class="col-span-2">
                  <label for="asymmetric-public-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.publicKey')}
                  </label>
                  <textarea
                    id="asymmetric-public-key"
                    bind:value={asymmetricPublicKey}
                    placeholder={t('crypto.asymmetric.publicKeyPlaceholder')}
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {:else}
                <!-- Private key for decryption -->
                <div class="col-span-2">
                  <label for="asymmetric-private-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.privateKey')}
                  </label>
                  <textarea
                    id="asymmetric-private-key"
                    bind:value={asymmetricPrivateKey}
                    placeholder={t('crypto.asymmetric.privateKeyPlaceholder')}
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {/if}
            {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA'}
              {#if asymmetricOperation === 'sign'}
                <!-- Private key for signing -->
                <div class="col-span-2">
                  <label for="asymmetric-private-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.privateKey')}
                  </label>
                  <textarea
                    id="asymmetric-private-key"
                    bind:value={asymmetricPrivateKey}
                    placeholder={t('crypto.asymmetric.privateKeyPlaceholder')}
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {:else}
                <!-- Public key for verification -->
                <div class="col-span-2">
                  <label for="asymmetric-public-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.publicKey')}
                  </label>
                  <textarea
                    id="asymmetric-public-key"
                    bind:value={asymmetricPublicKey}
                    placeholder={t('crypto.asymmetric.publicKeyPlaceholder')}
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {/if}
            {:else if asymmetricAlgorithm === 'ECDH'}
              <!-- Private key and peer public key for key exchange -->
              <div>
                <label for="asymmetric-private-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.asymmetric.privateKey')}
                </label>
                <textarea
                  id="asymmetric-private-key"
                  bind:value={asymmetricPrivateKey}
                  placeholder={t('crypto.asymmetric.privateKeyPlaceholder')}
                  class="textarea font-mono text-sm min-h-[120px]"
                ></textarea>
              </div>
              <div>
                <label for="asymmetric-peer-public-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.asymmetric.peerPublicKey')}
                </label>
                <textarea
                  id="asymmetric-peer-public-key"
                  bind:value={asymmetricPeerPublicKey}
                  placeholder={t('crypto.asymmetric.peerPublicKeyPlaceholder')}
                  class="textarea font-mono text-sm min-h-[120px]"
                ></textarea>
              </div>
            {:else if asymmetricAlgorithm === 'DSA'}
              <!-- DSA not supported message -->
              <div class="col-span-2">
                <div class="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                  <p class="text-sm text-yellow-800 dark:text-yellow-200">
                    {t('crypto.asymmetric.dsaNotSupported')}
                  </p>
                </div>
              </div>
            {/if}
          </div>

          <!-- Execute button -->
          <div class="flex gap-2 flex-shrink-0">
            <button
              onclick={executeAsymmetricOperation}
              class="px-4 py-2 text-white rounded-lg transition-colors font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
              style="background-color: #818089;"
              disabled={asymmetricAlgorithm === 'DSA'}
            >
              {#if asymmetricAlgorithm === 'RSA-OAEP'}
                {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.encrypt') : t('crypto.asymmetric.decrypt')}
              {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA'}
                {asymmetricOperation === 'sign' ? t('crypto.asymmetric.sign') : t('crypto.asymmetric.verify')}
              {:else if asymmetricAlgorithm === 'ECDH'}
                {t('crypto.asymmetric.keyExchange')}
              {:else if asymmetricAlgorithm === 'DSA'}
                {t('crypto.asymmetric.notSupported')}
              {/if}
            </button>
            <button
              onclick={clearAsymmetric}
              class="btn-secondary"
            >
              {t('common.clear')}
            </button>
          </div>

          <!-- Error message -->
          {#if asymmetricError}
            <div class="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex-shrink-0">
              <p class="text-sm text-red-800 dark:text-red-200">{asymmetricError}</p>
            </div>
          {/if}

          <!-- Input/Output area -->
          <div class="flex-1 grid grid-cols-2 gap-4 min-h-0">
            <!-- Input -->
            <div class="flex flex-col space-y-2">
              <div class="flex items-center justify-between h-6">
                <span class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {#if asymmetricAlgorithm === 'RSA-OAEP'}
                    {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.plaintext') : t('crypto.asymmetric.ciphertext')}
                  {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA'}
                    {asymmetricOperation === 'sign' ? t('crypto.asymmetric.message') : t('crypto.asymmetric.messageAndSignature')}
                  {:else if asymmetricAlgorithm === 'ECDH'}
                    {t('crypto.asymmetric.notApplicable')}
                  {:else if asymmetricAlgorithm === 'DSA'}
                    {t('crypto.asymmetric.notApplicable')}
                  {/if}
                </span>
                <div class="w-0"></div>
              </div>
              <textarea
                bind:value={asymmetricInput}
                placeholder={asymmetricAlgorithm === 'ECDH' || asymmetricAlgorithm === 'DSA'
                  ? t('crypto.asymmetric.notApplicable')
                  : (asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA') && asymmetricOperation === 'verify' 
                    ? t('crypto.asymmetric.messageAndSignaturePlaceholder')
                    : t('crypto.asymmetric.inputPlaceholder')}
                class="textarea font-mono text-sm flex-1 resize-none"
                disabled={asymmetricAlgorithm === 'ECDH' || asymmetricAlgorithm === 'DSA'}
              ></textarea>
            </div>

            <!-- Output -->
            <div class="flex flex-col space-y-2">
              <div class="flex items-center justify-between h-6">
                <span class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {#if asymmetricAlgorithm === 'RSA-OAEP'}
                    {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.ciphertext') : t('crypto.asymmetric.plaintext')}
                  {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA'}
                    {asymmetricOperation === 'sign' ? t('crypto.asymmetric.signature') : t('crypto.asymmetric.verificationResult')}
                  {:else if asymmetricAlgorithm === 'ECDH'}
                    {t('crypto.asymmetric.sharedSecret')}
                  {:else if asymmetricAlgorithm === 'DSA'}
                    {t('crypto.asymmetric.notApplicable')}
                  {/if}
                </span>
                {#if asymmetricOutput}
                  <button
                    onclick={copyAsymmetricToClipboard}
                    class="btn-secondary text-xs transition-all duration-200 {asymmetricCopied ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
                  >
                    {#if asymmetricCopied}
                      <span class="flex items-center gap-1">
                        <Check class="w-4 h-4" />
                        {t('common.copied')}
                      </span>
                    {:else}
                      <span class="flex items-center gap-1">
                        <Copy class="w-4 h-4" />
                        {t('common.copy')}
                      </span>
                    {/if}
                  </button>
                {:else}
                  <div class="w-0"></div>
                {/if}
              </div>
              <textarea
                value={asymmetricOutput}
                readonly
                placeholder={t('crypto.asymmetric.outputPlaceholder')}
                class="textarea font-mono text-sm flex-1 resize-none {asymmetricCopied ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
              ></textarea>
            </div>
          </div>
        </div>
      {:else if cryptoType === 'symmetric'}
        <!-- Symmetric Algorithm -->
        <div class="flex-1 flex flex-col space-y-4 min-h-0 overflow-y-auto">
          <!-- Algorithm selection -->
          <div class="flex-shrink-0">
            <label for="symmetric-algorithm" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
              {t('crypto.symmetric.algorithm')}
            </label>
            <select
              id="symmetric-algorithm"
              bind:value={symmetricAlgorithm}
              class="input w-full"
            >
              <option value="AES">AES</option>
              <option value="DES">DES</option>
              <option value="3DES">3DES</option>
              <option value="Rabbit">Rabbit</option>
              <option value="RC2">RC2</option>
              <option value="RC4">RC4</option>
            </select>
          </div>
          
          <!-- Mode selection for AES -->
          {#if symmetricAlgorithm === 'AES'}
            <div class="flex-shrink-0">
              <label for="aes-mode" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.symmetric.mode')}
              </label>
              <select
                id="aes-mode"
                bind:value={aesMode}
                class="input w-full"
              >
                <option value="GCM">GCM</option>
                <option value="CBC">CBC</option>
                <option value="CTR">CTR</option>
                <option value="CFB">CFB</option>
                <option value="OFB">OFB</option>
                <option value="ECB">ECB</option>
              </select>
            </div>
          {/if}
          
          <!-- Mode selection for DES -->
          {#if symmetricAlgorithm === 'DES'}
            <div class="flex-shrink-0">
              <label for="des-mode" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.symmetric.mode')}
              </label>
              <select
                id="des-mode"
                bind:value={desMode}
                class="input w-full"
              >
                <option value="ECB">ECB</option>
                <option value="CBC">CBC</option>
                <option value="CFB">CFB</option>
                <option value="OFB">OFB</option>
              </select>
            </div>
          {/if}
          
          <!-- Mode selection for 3DES -->
          {#if symmetricAlgorithm === '3DES'}
            <div class="flex-shrink-0">
              <label for="3des-mode" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.symmetric.mode')}
              </label>
              <select
                id="3des-mode"
                bind:value={tripleDesMode}
                class="input w-full"
              >
                <option value="ECB">ECB</option>
                <option value="CBC">CBC</option>
                <option value="CFB">CFB</option>
                <option value="OFB">OFB</option>
              </select>
            </div>
          {/if}
          
          <!-- Mode selection for RC2 -->
          {#if symmetricAlgorithm === 'RC2'}
            <div class="flex-shrink-0">
              <label for="rc2-mode" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.symmetric.mode')}
              </label>
              <select
                id="rc2-mode"
                bind:value={rc2Mode}
                class="input w-full"
              >
                <option value="ECB">ECB</option>
                <option value="CBC">CBC</option>
                <option value="CFB">CFB</option>
                <option value="OFB">OFB</option>
              </select>
            </div>
          {/if}
          
          <!-- Key and IV input (side by side) -->
          <div class="flex-shrink-0 grid grid-cols-2 gap-4">
            <!-- Key input -->
            <div class="{requiresIV(symmetricAlgorithm) ? '' : 'col-span-2'}">
              <label for="symmetric-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.symmetric.key')}
              </label>
              <input
                type="text"
                id="symmetric-key"
                bind:value={symmetricKey}
                placeholder={t('crypto.symmetric.keyPlaceholder')}
                class="input font-mono text-sm"
              />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                {getKeyLengthDescription(symmetricAlgorithm)}
              </p>
            </div>
            
            <!-- IV input -->
            {#if requiresIV(symmetricAlgorithm)}
              <div>
                <label for="symmetric-iv" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.symmetric.iv')}
                </label>
                <input
                  type="text"
                  id="symmetric-iv"
                  bind:value={symmetricIv}
                  placeholder={t('crypto.symmetric.ivPlaceholder')}
                  class="input font-mono text-sm"
                />
                <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {t('crypto.symmetric.ivDescription')}
                </p>
              </div>
            {/if}
          </div>
          
          <!-- Encrypt/Decrypt buttons -->
          <div class="flex gap-2 flex-shrink-0">
            <button
              onclick={() => { isEncrypting = true; encryptSymmetric(); }}
              class="px-4 py-2 rounded-lg transition-colors font-medium flex items-center justify-center gap-2 {isEncrypting
                ? 'text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-gray-100'}"
              style={isEncrypting ? 'background-color: #818089;' : ''}
            >
              {t('crypto.symmetric.encrypt')}
            </button>
            <button
              onclick={() => { isEncrypting = false; decryptSymmetric(); }}
              class="px-4 py-2 rounded-lg transition-colors font-medium flex items-center justify-center gap-2 {!isEncrypting
                ? 'text-white'
                : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-gray-100'}"
              style={!isEncrypting ? 'background-color: #818089;' : ''}
            >
              {t('crypto.symmetric.decrypt')}
            </button>
            <button
              onclick={clearSymmetric}
              class="btn-secondary"
            >
              {t('common.clear')}
            </button>
          </div>
          
          <!-- Error message -->
          {#if symmetricError}
            <div class="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex-shrink-0">
              <p class="text-sm text-red-800 dark:text-red-200">{symmetricError}</p>
            </div>
          {/if}
          
          <!-- Input/Output area -->
          <div class="flex-1 grid grid-cols-2 gap-4 min-h-0">
            <!-- Input -->
            <div class="flex flex-col space-y-2">
              <div class="flex items-center justify-between h-6">
                <span class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {isEncrypting ? t('crypto.symmetric.plaintext') : t('crypto.symmetric.ciphertext')}
                </span>
                <div class="w-0"></div>
              </div>
              <textarea
                bind:value={symmetricInput}
                placeholder={isEncrypting ? t('crypto.symmetric.plaintextPlaceholder') : t('crypto.symmetric.ciphertextPlaceholder')}
                class="textarea font-mono text-sm flex-1 resize-none"
              ></textarea>
            </div>
            
            <!-- Output -->
            <div class="flex flex-col space-y-2">
              <div class="flex items-center justify-between h-6">
                <span class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {isEncrypting ? t('crypto.symmetric.ciphertext') : t('crypto.symmetric.plaintext')}
                </span>
                {#if symmetricOutput}
                  <button
                    onclick={copySymmetricToClipboard}
                    class="btn-secondary text-xs transition-all duration-200 {symmetricCopied ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
                  >
                    {#if symmetricCopied}
                      <span class="flex items-center gap-1">
                        <Check class="w-4 h-4" />
                        {t('common.copied')}
                      </span>
                    {:else}
                      <span class="flex items-center gap-1">
                        <Copy class="w-4 h-4" />
                        {t('common.copy')}
                      </span>
                    {/if}
                  </button>
                {:else}
                  <div class="w-0"></div>
                {/if}
              </div>
              <textarea
                value={symmetricOutput}
                readonly
                placeholder={isEncrypting ? t('crypto.symmetric.ciphertextPlaceholder') : t('crypto.symmetric.plaintextPlaceholder')}
                class="textarea font-mono text-sm flex-1 resize-none {symmetricCopied ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
              ></textarea>
            </div>
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>

