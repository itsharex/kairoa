<script lang="ts">
  import { translationsStore } from '$lib/stores/i18n';
  import { Check, Copy } from 'lucide-svelte';
  import { page } from '$app/stores';
  import CryptoJS from 'crypto-js';
  import { browser } from '$app/environment';
  import { sm2, sm3, sm4 } from 'sm-crypto-v2';
  
  // 动态导入 Tauri API
  let invokeFn: ((cmd: string, args?: any) => Promise<any>) | null = $state(null);
  let isTauriAvailable = $state(false);
  
  if (browser) {
    if (typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      isTauriAvailable = true;
      import('@tauri-apps/api/core')
        .then((module) => {
          invokeFn = module.invoke;
        })
        .catch((err) => {
          console.error('Failed to load Tauri API:', err);
          isTauriAvailable = false;
        });
    }
  }
  
  type CryptoType = 'keygen' | 'asymmetric' | 'symmetric' | 'hash';
  
  let cryptoType = $state<CryptoType>('keygen');
  
  // Check URL parameter for type
  $effect(() => {
    const typeParam = $page.url.searchParams.get('type');
    if (typeParam === 'keygen') {
      cryptoType = 'keygen';
    } else if (typeParam === 'asymmetric') {
      cryptoType = 'asymmetric';
    } else if (typeParam === 'symmetric') {
      cryptoType = 'symmetric';
    } else if (typeParam === 'hash') {
      cryptoType = 'hash';
    }
  });
  
  // Key Generator state
  type KeyGenAlgorithm = 'RSA' | 'DSA' | 'ECDSA' | 'ECDH' | 'SM2';
  type KeySize = 1024 | 2048 | 3072 | 4096;
  type DsaKeySize = 1024 | 2048 | 3072;
  type KeyFormat = 'pem' | 'der';
  type EcCurve = 'P-256' | 'P-384' | 'P-521';
  
  let keyGenAlgorithm = $state<KeyGenAlgorithm>('RSA');
  let keySize = $state<KeySize>(2048);
  let dsaKeySize = $state<DsaKeySize>(2048);
  let ecCurve = $state<EcCurve>('P-256');
  let keyFormat = $state<KeyFormat>('pem');
  let publicKey = $state('');
  let privateKey = $state('');
  let isGenerating = $state(false);
  let publicKeyCopied = $state(false);
  let privateKeyCopied = $state(false);
  let keyGenError = $state('');
  
  // Symmetric algorithm state
  type SymmetricAlgorithm = 'AES' | 'DES' | '3DES' | 'Rabbit' | 'RC2' | 'RC4' | 'SM4';
  type BlockCipherMode = 'ECB' | 'CBC' | 'CFB' | 'OFB' | 'CTR' | 'GCM';
  let symmetricAlgorithm = $state<SymmetricAlgorithm>('AES');
  let aesMode = $state<BlockCipherMode>('GCM'); // Mode for AES
  let desMode = $state<BlockCipherMode>('CBC'); // Mode for DES
  let tripleDesMode = $state<BlockCipherMode>('CBC'); // Mode for 3DES
  let rc2Mode = $state<BlockCipherMode>('CBC'); // Mode for RC2
  let sm4Mode = $state<BlockCipherMode>('CBC'); // Mode for SM4
  let symmetricKey = $state('');
  let symmetricInput = $state('');
  let symmetricOutput = $state('');
  let symmetricIv = $state('');
  let isEncrypting = $state(true);
  let symmetricCopied = $state(false);
  let symmetricError = $state('');
  
  // Asymmetric algorithm state
  type AsymmetricAlgorithm = 'RSA-OAEP' | 'RSA-PSS' | 'ECDSA' | 'ECDH' | 'DSA' | 'SM2';
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

  // Password Hash state
  type HashAlgorithm = 'PBKDF2' | 'Scrypt' | 'Bcrypt' | 'Argon2' | 'SM3';
  let hashAlgorithm = $state<HashAlgorithm>('PBKDF2');
  let hashPassword = $state('');
  let hashSalt = $state('');
  let hashOutput = $state('');
  let hashIterations = $state(100000); // PBKDF2
  let hashKeyLength = $state(32); // bytes
  let hashCost = $state(14); // Bcrypt cost factor
  let scryptN = $state(16384); // Scrypt CPU/memory cost
  let scryptR = $state(8); // Scrypt block size
  let scryptP = $state(1); // Scrypt parallelization
  let argon2Memory = $state(65536); // Argon2 memory in KB
  let argon2Iterations = $state(3); // Argon2 iterations
  let argon2Parallelism = $state(4); // Argon2 parallelism
  let isHashing = $state(false);
  let hashCopied = $state(false);
  let hashError = $state('');
  let hashOperation = $state<'hash' | 'verify'>('hash');
  let hashToVerify = $state('');

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
    // Reset Key Generator state
    if (type === 'keygen') {
      publicKey = '';
      privateKey = '';
      publicKeyCopied = false;
      privateKeyCopied = false;
      keyGenError = '';
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
    // Reset hash state
    if (type === 'hash') {
      hashPassword = '';
      hashSalt = '';
      hashOutput = '';
      hashToVerify = '';
      hashCopied = false;
      hashError = '';
      hashOperation = 'hash';
    }
  }

  // Generate random salt
  function generateSalt(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  // Password Hash functions
  async function executeHashOperation() {
    hashError = '';
    hashOutput = '';
    
    if (!hashPassword.trim()) {
      hashError = t('crypto.hash.passwordRequired');
      return;
    }
    
    if (hashOperation === 'hash') {
      await hashPasswordFn();
    } else {
      await verifyPasswordFn();
    }
  }

  async function hashPasswordFn() {
    isHashing = true;
    try {
      if (hashAlgorithm === 'SM3') {
        if (!hashPassword.trim()) {
          hashError = t('crypto.hash.passwordRequired');
          return;
        }
        hashOutput = sm3(hashPassword);
      } else if (!isTauriAvailable || !invokeFn) {
        hashError = t('crypto.hash.tauriRequired');
        return;
      } else if (hashAlgorithm === 'PBKDF2') {
        await hashPBKDF2Tauri();
      } else if (hashAlgorithm === 'Scrypt') {
        await hashScryptTauri();
      } else if (hashAlgorithm === 'Bcrypt') {
        await hashBcryptTauri();
      } else if (hashAlgorithm === 'Argon2') {
        await hashArgon2Tauri();
      }
    } catch (error) {
      hashError = `Error: ${error instanceof Error ? error.message : String(error)}`;
    } finally {
      isHashing = false;
    }
  }

  async function verifyPasswordFn() {
    isHashing = true;
    try {
      if (hashAlgorithm === 'SM3') {
        if (!hashPassword.trim()) {
          hashError = t('crypto.hash.passwordRequired');
          return;
        }
        if (!hashToVerify.trim()) {
          hashError = t('crypto.hash.hashRequired');
          return;
        }
        const computedHash = sm3(hashPassword);
        if (computedHash.toLowerCase() === hashToVerify.toLowerCase()) {
          hashOutput = t('crypto.hash.verifySuccess');
        } else {
          hashError = t('crypto.hash.verifyFailed');
        }
      } else if (!isTauriAvailable || !invokeFn) {
        hashError = t('crypto.hash.tauriRequired');
        return;
      } else if (!hashToVerify.trim()) {
        hashError = t('crypto.hash.hashRequired');
        return;
      } else {
        let result;
        if (hashAlgorithm === 'PBKDF2') {
          result = await invokeFn('verify_pbkdf2', {
            request: { password: hashPassword, hash: hashToVerify }
          });
        } else if (hashAlgorithm === 'Scrypt') {
          result = await invokeFn('verify_scrypt', {
            request: { password: hashPassword, hash: hashToVerify }
          });
        } else if (hashAlgorithm === 'Bcrypt') {
          result = await invokeFn('verify_bcrypt', {
            request: { password: hashPassword, hash: hashToVerify }
          });
        } else if (hashAlgorithm === 'Argon2') {
          result = await invokeFn('verify_argon2', {
            request: { password: hashPassword, hash: hashToVerify }
          });
        }
        
        if (result && result.valid) {
          hashError = '';
          hashOutput = t('crypto.hash.verifySuccess');
        } else {
          hashError = t('crypto.hash.verifyFailed');
        }
      }
    } catch (error) {
      hashError = `Error: ${error instanceof Error ? error.message : String(error)}`;
    } finally {
      isHashing = false;
    }
  }

  async function hashPBKDF2Tauri() {
    if (!invokeFn) return;
    
    const result = await invokeFn('hash_pbkdf2', {
      request: {
        password: hashPassword,
        salt: hashSalt || null,
        algorithm: 'PBKDF2',
        iterations: hashIterations,
      }
    });
    
    hashOutput = result.hash;
    if (!hashSalt) {
      hashSalt = result.salt;
    }
  }

  async function hashScryptTauri() {
    if (!invokeFn) return;
    
    const result = await invokeFn('hash_scrypt', {
      request: {
        password: hashPassword,
        salt: hashSalt || null,
        algorithm: 'Scrypt',
        n: scryptN,
        r: scryptR,
        p: scryptP,
      }
    });
    
    hashOutput = result.hash;
    if (!hashSalt) {
      hashSalt = result.salt;
    }
  }

  async function hashBcryptTauri() {
    if (!invokeFn) return;
    
    const result = await invokeFn('hash_bcrypt', {
      request: {
        password: hashPassword,
        salt: null,
        algorithm: 'Bcrypt',
        iterations: hashCost,
      }
    });
    
    hashOutput = result.hash;
  }

  async function hashArgon2Tauri() {
    if (!invokeFn) return;
    
    const result = await invokeFn('hash_argon2', {
      request: {
        password: hashPassword,
        salt: hashSalt || null,
        algorithm: 'Argon2',
        memory: argon2Memory,
        argon2_iterations: argon2Iterations,
        parallelism: argon2Parallelism,
      }
    });
    
    hashOutput = result.hash;
    if (!hashSalt) {
      hashSalt = result.salt;
    }
  }

  function generateHashSalt() {
    hashSalt = generateSalt();
  }

  function clearHash() {
    hashPassword = '';
    hashSalt = '';
    hashOutput = '';
    hashToVerify = '';
    hashError = '';
    hashCopied = false;
  }

  async function copyHash() {
    if (hashOutput) {
      try {
        await navigator.clipboard.writeText(hashOutput);
        hashCopied = true;
        setTimeout(() => {
          hashCopied = false;
        }, 2000);
      } catch (err) {
        console.error('Failed to copy:', err);
      }
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
    keyGenError = '';

    try {
      if (keyGenAlgorithm === 'RSA') {
        await generateRSAKeyPair();
      } else if (keyGenAlgorithm === 'DSA') {
        await generateDSAKeyPair();
      } else if (keyGenAlgorithm === 'ECDSA') {
        await generateECDSAKeyPair();
      } else if (keyGenAlgorithm === 'ECDH') {
        await generateECDHKeyPair();
      } else if (keyGenAlgorithm === 'SM2') {
        generateSM2KeyPair();
      }
    } catch (error) {
      console.error('Error generating key pair:', error);
      keyGenError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    } finally {
      isGenerating = false;
    }
  }

  async function generateRSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: keySize,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
    publicKey = await exportPublicKey(keyPair.publicKey, keyFormat);
    privateKey = await exportPrivateKey(keyPair.privateKey, keyFormat);
  }

  async function generateDSAKeyPair() {
    if (!isTauriAvailable || !invokeFn) {
      keyGenError = t('keyGenerator.tauriRequired');
      return;
    }
    
    const result = await invokeFn('generate_dsa_keypair', {
      keySize: dsaKeySize,
      format: keyFormat
    });
    publicKey = result.public_key;
    privateKey = result.private_key;
  }

  async function generateECDSAKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: ecCurve,
      },
      true,
      ['sign', 'verify']
    );
    publicKey = await exportPublicKey(keyPair.publicKey, keyFormat);
    privateKey = await exportPrivateKey(keyPair.privateKey, keyFormat);
  }

  async function generateECDHKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: ecCurve,
      },
      true,
      ['deriveKey', 'deriveBits']
    );
    publicKey = await exportPublicKey(keyPair.publicKey, keyFormat);
    privateKey = await exportPrivateKey(keyPair.privateKey, keyFormat);
  }

  function generateSM2KeyPair() {
    const keyPair = sm2.generateKeyPairHex();
    // SM2 keys are in hex format, convert to PEM-like format for consistency
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
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

  function clearKeyGen() {
    publicKey = '';
    privateKey = '';
    publicKeyCopied = false;
    privateKeyCopied = false;
    keyGenError = '';
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
  
  // DSA Sign
  async function signDSA() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!isTauriAvailable || !invokeFn) {
      asymmetricError = t('crypto.asymmetric.dsaTauriRequired');
      return;
    }
    
    if (!asymmetricPrivateKey.trim()) {
      asymmetricError = t('crypto.asymmetric.privateKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.messageRequired');
      return;
    }
    
    try {
      const result = await invokeFn('dsa_sign', {
        privateKeyPem: asymmetricPrivateKey,
        message: asymmetricInput
      });
      
      // 输出格式：message|signature
      asymmetricOutput = `${asymmetricInput}|${result.signature}`;
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : String(error)}`;
    }
  }
  
  // DSA Verify
  async function verifyDSA() {
    asymmetricError = '';
    asymmetricOutput = '';
    
    if (!isTauriAvailable || !invokeFn) {
      asymmetricError = t('crypto.asymmetric.dsaTauriRequired');
      return;
    }
    
    if (!asymmetricPublicKey.trim()) {
      asymmetricError = t('crypto.asymmetric.publicKeyRequired');
      return;
    }
    
    if (!asymmetricInput.trim()) {
      asymmetricError = t('crypto.asymmetric.messageAndSignatureRequired');
      return;
    }
    
    try {
      // Parse message|signature format
      const parts = asymmetricInput.split('|');
      if (parts.length !== 2) {
        asymmetricError = t('crypto.asymmetric.invalidMessageSignatureFormat');
        return;
      }
      
      const [message, signature] = parts;
      
      const result = await invokeFn('dsa_verify', {
        publicKeyPem: asymmetricPublicKey,
        message: message,
        signature: signature
      });
      
      asymmetricOutput = result.valid 
        ? t('crypto.asymmetric.signatureValid')
        : t('crypto.asymmetric.signatureInvalid');
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : String(error)}`;
    }
  }
  
  // SM2 Encrypt
  function encryptSM2() {
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
      const encrypted = sm2.doEncrypt(asymmetricInput, asymmetricPublicKey);
      asymmetricOutput = encrypted;
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // SM2 Decrypt
  function decryptSM2() {
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
      const decrypted = sm2.doDecrypt(asymmetricInput, asymmetricPrivateKey);
      asymmetricOutput = decrypted;
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Invalid encrypted data or key'}`;
    }
  }
  
  // SM2 Sign
  function signSM2() {
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
      const signature = sm2.doSignature(asymmetricInput, asymmetricPrivateKey);
      asymmetricOutput = signature;
    } catch (error) {
      asymmetricError = `Error: ${error instanceof Error ? error.message : 'Unknown error'}`;
    }
  }
  
  // SM2 Verify
  function verifySM2() {
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
      // Parse message|signature format
      const parts = asymmetricInput.split('|');
      if (parts.length !== 2) {
        asymmetricError = t('crypto.asymmetric.invalidFormat');
        return;
      }
      
      const message = parts[0];
      const signature = parts[1];
      
      const isValid = sm2.doVerifySignature(message, signature, asymmetricPublicKey);
      asymmetricOutput = isValid ? t('crypto.asymmetric.verifySuccess') : t('crypto.asymmetric.verifyFailed');
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
      if (asymmetricOperation === 'sign') {
        await signDSA();
      } else if (asymmetricOperation === 'verify') {
        await verifyDSA();
      }
    } else if (asymmetricAlgorithm === 'SM2') {
      if (asymmetricOperation === 'encrypt') {
        encryptSM2();
      } else if (asymmetricOperation === 'decrypt') {
        decryptSM2();
      } else if (asymmetricOperation === 'sign') {
        signSM2();
      } else if (asymmetricOperation === 'verify') {
        verifySM2();
      }
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
    // SM4 depends on selected mode
    if (algorithm === 'SM4') {
      return sm4Mode !== 'ECB';
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
      case 'SM4':
        if (sm4Mode === 'ECB') {
          return 0;
        } else if (sm4Mode === 'GCM') {
          return 12;
        } else {
          return 16; // CBC, CFB, OFB, CTR
        }
      default:
        return 16;
    }
  }
  
  // Check if algorithm uses Web Crypto API
  // Web Crypto API only supports AES-GCM, AES-CBC, AES-CTR
  function usesWebCryptoAPI(algorithm: SymmetricAlgorithm): boolean {
    return algorithm === 'AES' && (aesMode === 'GCM' || aesMode === 'CBC' || aesMode === 'CTR');
  }

  function usesSM4(algorithm: SymmetricAlgorithm): boolean {
    return algorithm === 'SM4';
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
      case 'SM4':
        return [16]; // SM4 uses 128-bit (16 bytes) key
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
      case 'SM4':
        return `${algorithmName}: 16 bytes (128 bits)`;
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
      case 'SM4':
        return `SM4-${sm4Mode}`;
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
      // Use SM4 for SM4 algorithm
      if (usesSM4(symmetricAlgorithm)) {
        const keyBuffer = textToArrayBuffer(symmetricKey);
        const keyLength = keyBuffer.byteLength;
        const validLengths = getValidKeyLengths(symmetricAlgorithm);
        if (!validLengths.includes(keyLength)) {
          const algorithmName = getAlgorithmDisplayName();
          const expectedLengths = getKeyLengthDescription(symmetricAlgorithm);
          symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${expectedLengths})`;
          return;
        }
        
        // Convert key to hex string
        const keyHex = arrayBufferToHex(keyBuffer);
        
        // Prepare IV
        let ivHex: string | undefined;
        if (symmetricIv.trim()) {
          const ivText = symmetricIv.trim();
          if (isValidHex(ivText)) {
            ivHex = ivText;
          } else {
            const ivBuffer = textToArrayBuffer(ivText);
            ivHex = arrayBufferToHex(ivBuffer);
          }
          const ivLength = ivHex.length / 2;
          const expectedIvLength = getIVLength(symmetricAlgorithm);
          if (ivLength !== expectedIvLength) {
            symmetricError = t('crypto.symmetric.invalidIvLength') + ` (Current: ${ivLength} bytes, Expected: ${expectedIvLength} bytes)`;
            return;
          }
        } else {
          // Generate random IV
          const ivLength = getIVLength(symmetricAlgorithm);
          const ivBytes = crypto.getRandomValues(new Uint8Array(ivLength));
          ivHex = arrayBufferToHex(ivBytes.buffer);
          symmetricIv = ivHex;
        }
        
        // Convert input to hex
        const inputHex = arrayBufferToHex(new TextEncoder().encode(symmetricInput));
        
        // SM4 encryption
        const mode = sm4Mode.toLowerCase() as 'cbc' | 'ecb' | 'gcm';
        const options: any = {
          mode: mode,
          output: 'hex'
        };
        
        if (mode !== 'ecb' && ivHex) {
          options.iv = hexToArrayBuffer(ivHex);
        }
        
        const encrypted = sm4.encrypt(inputHex, keyHex, 1, options);
        
        if (mode === 'gcm' && typeof encrypted === 'object' && 'output' in encrypted) {
          symmetricOutput = encrypted.output as string;
          if (encrypted.tag) {
            symmetricOutput += '|' + (typeof encrypted.tag === 'string' ? encrypted.tag : arrayBufferToHex(encrypted.tag.buffer));
          }
        } else {
          symmetricOutput = encrypted as string;
        }
      } else if (usesWebCryptoAPI(symmetricAlgorithm)) {
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
      // Use SM4 for SM4 algorithm
      if (usesSM4(symmetricAlgorithm)) {
        const keyBuffer = textToArrayBuffer(symmetricKey);
        const keyLength = keyBuffer.byteLength;
        const validLengths = getValidKeyLengths(symmetricAlgorithm);
        if (!validLengths.includes(keyLength)) {
          const algorithmName = getAlgorithmDisplayName();
          const expectedLengths = getKeyLengthDescription(symmetricAlgorithm);
          symmetricError = t('crypto.symmetric.invalidKeyLength') + ` (${algorithmName}: Current: ${keyLength} bytes, Expected: ${expectedLengths})`;
          return;
        }
        
        // Convert key to hex string
        const keyHex = arrayBufferToHex(keyBuffer);
        
        // Prepare IV
        let ivHex: string | undefined;
        if (symmetricIv.trim()) {
          const ivText = symmetricIv.trim();
          if (isValidHex(ivText)) {
            ivHex = ivText;
          } else {
            const ivBuffer = textToArrayBuffer(ivText);
            ivHex = arrayBufferToHex(ivBuffer);
          }
          const ivLength = ivHex.length / 2;
          const expectedIvLength = getIVLength(symmetricAlgorithm);
          if (ivLength !== expectedIvLength) {
            symmetricError = t('crypto.symmetric.invalidIvLength') + ` (Current: ${ivLength} bytes, Expected: ${expectedIvLength} bytes)`;
            return;
          }
        } else if (sm4Mode !== 'ECB') {
          const expectedIvLength = getIVLength(symmetricAlgorithm);
          symmetricError = t('crypto.symmetric.ivRequired') + ` (Required: ${expectedIvLength} bytes)`;
          return;
        }
        
        // Parse input (hex string)
        let inputHex = symmetricInput.trim();
        let tagHex: string | undefined;
        
        // Check if input contains tag (for GCM mode)
        if (sm4Mode === 'GCM' && inputHex.includes('|')) {
          const parts = inputHex.split('|');
          inputHex = parts[0];
          tagHex = parts[1];
        }
        
        // SM4 decryption
        const mode = sm4Mode.toLowerCase() as 'cbc' | 'ecb' | 'gcm';
        const options: any = {
          mode: mode,
          output: 'hex'
        };
        
        if (mode !== 'ecb' && ivHex) {
          options.iv = hexToArrayBuffer(ivHex);
        }
        
        if (mode === 'gcm' && tagHex) {
          options.tag = hexToArrayBuffer(tagHex);
        }
        
        const decrypted = sm4.decrypt(inputHex, keyHex, 0, options);
        const decryptedHex = typeof decrypted === 'string' ? decrypted : arrayBufferToHex(decrypted.buffer);
        
        // Convert hex to text
        try {
          const decryptedBytes = hexToArrayBuffer(decryptedHex);
          symmetricOutput = new TextDecoder().decode(decryptedBytes);
        } catch (e) {
          symmetricError = `Error: ${e instanceof Error ? e.message : 'Failed to decode decrypted data'}`;
        }
      } else if (usesWebCryptoAPI(symmetricAlgorithm)) {
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
            onclick={() => switchCryptoType('keygen')}
            class="px-4 py-2 relative transition-colors font-medium {cryptoType === 'keygen'
              ? 'text-primary-600 dark:text-primary-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}"
          >
            {t('keyGenerator.title')}
            {#if cryptoType === 'keygen'}
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
          <button
            onclick={() => switchCryptoType('hash')}
            class="px-4 py-2 relative transition-colors font-medium {cryptoType === 'hash'
              ? 'text-primary-600 dark:text-primary-400'
              : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}"
          >
            {t('crypto.hash.title')}
            {#if cryptoType === 'hash'}
              <span class="absolute bottom-0 left-0 right-0 h-0.5 bg-primary-600 dark:text-primary-400"></span>
            {/if}
          </button>
        </div>
      </div>

      <!-- Asymmetric Key Generator -->
      {#if cryptoType === 'keygen'}
        <div class="flex-1 flex flex-col space-y-6 min-h-0 overflow-y-auto">
          <!-- 配置区域 -->
          <div class="flex-shrink-0">
            <div class="space-y-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label for="keygen-algorithm" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('keyGenerator.algorithm')}
                  </label>
                  <select
                    id="keygen-algorithm"
                    bind:value={keyGenAlgorithm}
                    class="input w-full"
                  >
                    <option value="RSA">RSA</option>
                    <option value="DSA">DSA</option>
                    <option value="ECDSA">ECDSA</option>
                    <option value="ECDH">ECDH</option>
                    <option value="SM2">SM2 (国密)</option>
                  </select>
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {#if keyGenAlgorithm === 'RSA'}
                      {t('keyGenerator.rsaDescription')}
                    {:else if keyGenAlgorithm === 'DSA'}
                      {t('keyGenerator.dsaDescription')}
                    {:else if keyGenAlgorithm === 'ECDSA'}
                      {t('keyGenerator.ecdsaDescription')}
                    {:else if keyGenAlgorithm === 'ECDH'}
                      {t('keyGenerator.ecdhDescription')}
                    {:else if keyGenAlgorithm === 'SM2'}
                      {t('keyGenerator.sm2Description')}
                    {/if}
                  </p>
                </div>

                {#if keyGenAlgorithm === 'RSA'}
                  <div>
                    <label for="key-size" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                      {t('keyGenerator.keySize')}
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
                  </div>
                {:else if keyGenAlgorithm === 'DSA'}
                  <div>
                    <label for="dsa-key-size" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                      {t('keyGenerator.keySize')}
                    </label>
                    <select
                      id="dsa-key-size"
                      bind:value={dsaKeySize}
                      class="input w-full"
                    >
                      <option value={1024}>1024 bits (L=1024, N=160) - {t('keyGenerator.deprecated')}</option>
                      <option value={2048}>2048 bits (L=2048, N=256) - {t('keyGenerator.recommended')}</option>
                      <option value={3072}>3072 bits (L=3072, N=256) - {t('keyGenerator.slower')}</option>
                    </select>
                    <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                      {t('keyGenerator.dsaKeySizeHint')}
                    </p>
                  </div>
                {:else if keyGenAlgorithm === 'ECDSA' || keyGenAlgorithm === 'ECDH'}
                  <div>
                    <label for="ec-curve" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                      {t('keyGenerator.curve')}
                    </label>
                    <select
                      id="ec-curve"
                      bind:value={ecCurve}
                      class="input w-full"
                    >
                      <option value="P-256">P-256 (256 bits)</option>
                      <option value="P-384">P-384 (384 bits)</option>
                      <option value="P-521">P-521 (521 bits)</option>
                    </select>
                  </div>
                {/if}

                <div>
                  <label for="key-format" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('keyGenerator.keyFormat')}
                  </label>
                  <select
                    id="key-format"
                    bind:value={keyFormat}
                    class="input w-full"
                  >
                    <option value="pem">PEM</option>
                    <option value="der">DER (Hex)</option>
                  </select>
                </div>
              </div>

              {#if keyGenAlgorithm === 'DSA' && !isTauriAvailable}
                <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-3">
                  <p class="text-sm text-yellow-800 dark:text-yellow-200">
                    <strong>{t('keyGenerator.tauriRequired')}</strong> {t('keyGenerator.tauriRequiredDescription')}
                  </p>
                </div>
              {/if}

              {#if isGenerating && keyGenAlgorithm === 'DSA'}
                <div class="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                  <div class="flex items-center gap-2">
                    <div class="animate-spin rounded-full h-4 w-4 border-2 border-blue-600 border-t-transparent"></div>
                    <p class="text-sm text-blue-800 dark:text-blue-200">
                      {t('keyGenerator.dsaGenerating')}
                    </p>
                  </div>
                </div>
              {/if}

              <div class="flex gap-2">
                <button
                  onclick={generateKeyPair}
                  disabled={isGenerating || (keyGenAlgorithm === 'DSA' && !isTauriAvailable)}
                  class="px-4 py-2 text-white rounded-lg transition-colors font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
                  style="background-color: #818089;"
                >
                  {#if isGenerating}
                    {t('keyGenerator.generating')}
                  {:else}
                    {t('keyGenerator.generate')}
                  {/if}
                </button>
                <button
                  onclick={clearKeyGen}
                  disabled={isGenerating}
                  class="btn-secondary"
                >
                  {t('keyGenerator.clear')}
                </button>
              </div>

              {#if keyGenError}
                <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                  <p class="text-sm text-red-800 dark:text-red-200">
                    <strong>{t('common.error')}:</strong> {keyGenError}
                  </p>
                </div>
              {/if}
            </div>
          </div>

          <!-- 公钥卡片 -->
          {#if publicKey}
            <div class="flex-shrink-0">
              <div class="space-y-4">
                <div class="flex items-center justify-between">
                  <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    {t('keyGenerator.publicKey')}
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
                    {t('keyGenerator.privateKey')}
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
                    <strong>{t('keyGenerator.warning')}</strong> {t('keyGenerator.warningDescription')}
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
              <option value="DSA">DSA (Sign/Verify)</option>
              <option value="SM2">SM2 (国密 - Encryption/Decryption/Sign/Verify)</option>
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
                <option value="sign">{t('crypto.asymmetric.sign')}</option>
                <option value="verify">{t('crypto.asymmetric.verify')}</option>
              {:else if asymmetricAlgorithm === 'SM2'}
                <option value="encrypt">{t('crypto.asymmetric.encrypt')}</option>
                <option value="decrypt">{t('crypto.asymmetric.decrypt')}</option>
                <option value="sign">{t('crypto.asymmetric.sign')}</option>
                <option value="verify">{t('crypto.asymmetric.verify')}</option>
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
            {:else if asymmetricAlgorithm === 'SM2'}
              {#if asymmetricOperation === 'encrypt' || asymmetricOperation === 'verify'}
                <!-- Public key for encryption or verification -->
                <div class="col-span-2">
                  <label for="asymmetric-public-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.publicKey')}
                  </label>
                  <textarea
                    id="asymmetric-public-key"
                    bind:value={asymmetricPublicKey}
                    placeholder="Enter SM2 public key (hex format)..."
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {:else}
                <!-- Private key for decryption or signing -->
                <div class="col-span-2">
                  <label for="asymmetric-private-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.privateKey')}
                  </label>
                  <textarea
                    id="asymmetric-private-key"
                    bind:value={asymmetricPrivateKey}
                    placeholder="Enter SM2 private key (hex format)..."
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
              <!-- DSA Info -->
              <div class="col-span-2">
                <div class="p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                  <p class="text-sm text-blue-800 dark:text-blue-200">
                    <strong>{t('crypto.asymmetric.dsaInfo')}</strong> {t('crypto.asymmetric.dsaInfoDescription')}
                  </p>
                </div>
              </div>
              
              {#if asymmetricOperation === 'sign'}
                <!-- Private key for signing -->
                <div>
                  <label for="dsa-private-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.privateKey')}
                  </label>
                  <textarea
                    id="dsa-private-key"
                    bind:value={asymmetricPrivateKey}
                    placeholder={t('crypto.asymmetric.privateKeyPlaceholder')}
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {:else if asymmetricOperation === 'verify'}
                <!-- Public key for verification -->
                <div>
                  <label for="dsa-public-key" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.asymmetric.publicKey')}
                  </label>
                  <textarea
                    id="dsa-public-key"
                    bind:value={asymmetricPublicKey}
                    placeholder={t('crypto.asymmetric.publicKeyPlaceholder')}
                    class="textarea font-mono text-sm min-h-[120px]"
                  ></textarea>
                </div>
              {/if}
              
              {#if !isTauriAvailable}
                <div class="col-span-2">
                  <div class="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                    <p class="text-sm text-yellow-800 dark:text-yellow-200">
                      {t('crypto.asymmetric.dsaTauriRequired')}
                    </p>
                  </div>
                </div>
              {/if}
            {/if}
          </div>

          <!-- Execute button -->
          <div class="flex gap-2 flex-shrink-0">
            <button
              onclick={executeAsymmetricOperation}
              class="px-4 py-2 text-white rounded-lg transition-colors font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
              style="background-color: #818089;"
              disabled={asymmetricAlgorithm === 'DSA' && !isTauriAvailable}
            >
              {#if asymmetricAlgorithm === 'RSA-OAEP'}
                {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.encrypt') : t('crypto.asymmetric.decrypt')}
              {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA' || asymmetricAlgorithm === 'DSA'}
                {asymmetricOperation === 'sign' ? t('crypto.asymmetric.sign') : t('crypto.asymmetric.verify')}
              {:else if asymmetricAlgorithm === 'SM2'}
                {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.encrypt') 
                  : asymmetricOperation === 'decrypt' ? t('crypto.asymmetric.decrypt')
                  : asymmetricOperation === 'sign' ? t('crypto.asymmetric.sign')
                  : t('crypto.asymmetric.verify')}
              {:else if asymmetricAlgorithm === 'ECDH'}
                {t('crypto.asymmetric.keyExchange')}
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
                  {:else if asymmetricAlgorithm === 'SM2'}
                    {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.plaintext')
                      : asymmetricOperation === 'decrypt' ? t('crypto.asymmetric.ciphertext')
                      : asymmetricOperation === 'sign' ? t('crypto.asymmetric.message')
                      : t('crypto.asymmetric.messageAndSignature')}
                  {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA' || asymmetricAlgorithm === 'DSA'}
                    {asymmetricOperation === 'sign' ? t('crypto.asymmetric.message') : t('crypto.asymmetric.messageAndSignature')}
                  {:else if asymmetricAlgorithm === 'ECDH'}
                    {t('crypto.asymmetric.notApplicable')}
                  {/if}
                </span>
                <div class="w-0"></div>
              </div>
              <textarea
                bind:value={asymmetricInput}
                placeholder={asymmetricAlgorithm === 'ECDH'
                  ? t('crypto.asymmetric.notApplicable')
                  : ((asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA' || asymmetricAlgorithm === 'DSA' || asymmetricAlgorithm === 'SM2') && asymmetricOperation === 'verify')
                    ? t('crypto.asymmetric.messageAndSignaturePlaceholder')
                    : t('crypto.asymmetric.inputPlaceholder')}
                class="textarea font-mono text-sm flex-1 resize-none"
                disabled={asymmetricAlgorithm === 'ECDH'}
              ></textarea>
            </div>

            <!-- Output -->
            <div class="flex flex-col space-y-2">
              <div class="flex items-center justify-between h-6">
                <span class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  {#if asymmetricAlgorithm === 'RSA-OAEP'}
                    {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.ciphertext') : t('crypto.asymmetric.plaintext')}
                  {:else if asymmetricAlgorithm === 'SM2'}
                    {asymmetricOperation === 'encrypt' ? t('crypto.asymmetric.ciphertext')
                      : asymmetricOperation === 'decrypt' ? t('crypto.asymmetric.plaintext')
                      : asymmetricOperation === 'sign' ? t('crypto.asymmetric.signature')
                      : t('crypto.asymmetric.verificationResult')}
                  {:else if asymmetricAlgorithm === 'RSA-PSS' || asymmetricAlgorithm === 'ECDSA' || asymmetricAlgorithm === 'DSA'}
                    {asymmetricOperation === 'sign' ? t('crypto.asymmetric.signature') : t('crypto.asymmetric.verificationResult')}
                  {:else if asymmetricAlgorithm === 'ECDH'}
                    {t('crypto.asymmetric.sharedSecret')}
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
              <option value="SM4">SM4 (国密)</option>
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
          
          <!-- Mode selection for SM4 -->
          {#if symmetricAlgorithm === 'SM4'}
            <div class="flex-shrink-0">
              <label for="sm4-mode" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                {t('crypto.symmetric.mode')}
              </label>
              <select
                id="sm4-mode"
                bind:value={sm4Mode}
                class="input w-full"
              >
                <option value="ECB">ECB</option>
                <option value="CBC">CBC</option>
                <option value="GCM">GCM</option>
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
      {:else if cryptoType === 'hash'}
        <!-- Password Hash -->
        <div class="flex-1 flex flex-col space-y-4 min-h-0 overflow-y-auto">
          <!-- Configuration -->
          <div class="flex-shrink-0 space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="hash-algorithm" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.hash.algorithm')}
                </label>
                <select
                  id="hash-algorithm"
                  bind:value={hashAlgorithm}
                  class="input w-full"
                >
                  <option value="PBKDF2">PBKDF2</option>
                  <option value="Scrypt">Scrypt</option>
                  <option value="Bcrypt">Bcrypt</option>
                  <option value="SM3">SM3 (国密)</option>
                  <option value="Argon2">Argon2</option>
                </select>
              </div>

              <div>
                <label for="hash-operation" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.hash.operation')}
                </label>
                <select
                  id="hash-operation"
                  bind:value={hashOperation}
                  class="input w-full"
                >
                  <option value="hash">{t('crypto.hash.hash')}</option>
                  <option value="verify">{t('crypto.hash.verify')}</option>
                </select>
              </div>
            </div>

            <!-- Algorithm-specific parameters -->
            {#if hashAlgorithm === 'PBKDF2'}
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label for="pbkdf2-iterations" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.iterations')}
                  </label>
                  <input
                    type="number"
                    id="pbkdf2-iterations"
                    bind:value={hashIterations}
                    min="1000"
                    max="1000000"
                    class="input w-full"
                  />
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {t('crypto.hash.iterationsHint')}
                  </p>
                </div>
                <div>
                  <label for="pbkdf2-keylen" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.keyLength')}
                  </label>
                  <input
                    type="number"
                    id="pbkdf2-keylen"
                    bind:value={hashKeyLength}
                    min="16"
                    max="64"
                    class="input w-full"
                  />
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {t('crypto.hash.keyLengthHint')}
                  </p>
                </div>
              </div>
            {:else if hashAlgorithm === 'Scrypt'}
              <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label for="scrypt-n" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    N (CPU/Memory)
                  </label>
                  <select
                    id="scrypt-n"
                    bind:value={scryptN}
                    class="input w-full"
                  >
                    <option value={1024}>1024</option>
                    <option value={2048}>2048</option>
                    <option value={4096}>4096</option>
                    <option value={8192}>8192</option>
                    <option value={16384}>16384 (推荐)</option>
                    <option value={32768}>32768</option>
                  </select>
                </div>
                <div>
                  <label for="scrypt-r" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    r (Block Size)
                  </label>
                  <input
                    type="number"
                    id="scrypt-r"
                    bind:value={scryptR}
                    min="1"
                    max="16"
                    class="input w-full"
                  />
                </div>
                <div>
                  <label for="scrypt-p" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    p (Parallelism)
                  </label>
                  <input
                    type="number"
                    id="scrypt-p"
                    bind:value={scryptP}
                    min="1"
                    max="8"
                    class="input w-full"
                  />
                </div>
              </div>
            {:else if hashAlgorithm === 'Bcrypt'}
              <div>
                <label for="bcrypt-cost" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.hash.cost')}
                </label>
                <input
                  type="number"
                  id="bcrypt-cost"
                  bind:value={hashCost}
                  min="4"
                  max="31"
                  class="input w-full"
                />
                <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {t('crypto.hash.costHint')}
                </p>
              </div>
            {:else if hashAlgorithm === 'Argon2'}
              <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label for="argon2-memory" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.memory')}
                  </label>
                  <input
                    type="number"
                    id="argon2-memory"
                    bind:value={argon2Memory}
                    min="8192"
                    max="1048576"
                    step="1024"
                    class="input w-full"
                  />
                  <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {t('crypto.hash.memoryHint')}
                  </p>
                </div>
                <div>
                  <label for="argon2-iterations" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.iterations')}
                  </label>
                  <input
                    type="number"
                    id="argon2-iterations"
                    bind:value={argon2Iterations}
                    min="1"
                    max="10"
                    class="input w-full"
                  />
                </div>
                <div>
                  <label for="argon2-parallelism" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.parallelism')}
                  </label>
                  <input
                    type="number"
                    id="argon2-parallelism"
                    bind:value={argon2Parallelism}
                    min="1"
                    max="16"
                    class="input w-full"
                  />
                </div>
              </div>
            {/if}

            {#if !isTauriAvailable}
              <div class="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <p class="text-sm text-yellow-800 dark:text-yellow-200">
                  {t('crypto.hash.tauriRequired')}
                </p>
              </div>
            {/if}

            <!-- Password and Salt -->
            <div class="grid grid-cols-1 gap-4">
              <div>
                <label for="hash-password" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.hash.password')}
                </label>
                <input
                  type="password"
                  id="hash-password"
                  bind:value={hashPassword}
                  placeholder={t('crypto.hash.passwordPlaceholder')}
                  class="input w-full"
                />
              </div>

              <div>
                <label for="hash-salt" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                  {t('crypto.hash.salt')}
                </label>
                <div class="flex gap-2">
                  <input
                    type="text"
                    id="hash-salt"
                    bind:value={hashSalt}
                    placeholder={t('crypto.hash.saltPlaceholder')}
                    class="input flex-1"
                  />
                  <button
                    onclick={generateHashSalt}
                    class="btn-secondary whitespace-nowrap"
                  >
                    {t('crypto.hash.generateSalt')}
                  </button>
                </div>
                <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                  {t('crypto.hash.saltHint')}
                </p>
              </div>

              {#if hashOperation === 'verify'}
                <div>
                  <label for="hash-verify" class="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.hashToVerify')}
                  </label>
                  <input
                    type="text"
                    id="hash-verify"
                    bind:value={hashToVerify}
                    placeholder={t('crypto.hash.hashToVerifyPlaceholder')}
                    class="input w-full font-mono text-sm"
                  />
                </div>
              {/if}
            </div>

            <!-- Action buttons -->
            <div class="flex gap-2">
              <button
                onclick={executeHashOperation}
                disabled={isHashing || !isTauriAvailable}
                class="px-4 py-2 text-white rounded-lg transition-colors font-medium hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed"
                style="background-color: #818089;"
              >
                {#if isHashing}
                  {t('crypto.hash.hashing')}
                {:else}
                  {hashOperation === 'hash' ? t('crypto.hash.hash') : t('crypto.hash.verify')}
                {/if}
              </button>
              <button
                onclick={clearHash}
                disabled={isHashing}
                class="btn-secondary"
              >
                {t('common.clear')}
              </button>
            </div>

            {#if hashError}
              <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <p class="text-sm text-red-800 dark:text-red-200">
                  {hashError}
                </p>
              </div>
            {/if}
          </div>

          <!-- Output -->
          {#if hashOutput}
            <div class="flex-shrink-0">
              <div class="space-y-2">
                <div class="flex items-center justify-between">
                  <div class="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    {t('crypto.hash.output')}
                  </div>
                  <button
                    onclick={copyHash}
                    class="btn-secondary whitespace-nowrap transition-all duration-200 {hashCopied ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
                  >
                    {#if hashCopied}
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
                  value={hashOutput}
                  readonly
                  class="textarea font-mono text-sm min-h-[100px] {hashCopied ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
                ></textarea>
              </div>
            </div>
          {/if}
        </div>
      {/if}
    </div>
  </div>
</div>

