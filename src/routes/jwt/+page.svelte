<script lang="ts">
  import { translationsStore } from '$lib/stores/i18n';
  import { Copy, Check, Trash2 } from 'lucide-svelte';

  let jwtToken = $state('');
  let decodedHeader = $state<string>('');
  let decodedPayload = $state<string>('');
  let signature = $state<string>('');
  let error = $state<string>('');
  let copied = $state<{ header: boolean; payload: boolean; signature: boolean }>({
    header: false,
    payload: false,
    signature: false
  });

  let translations = $derived($translationsStore);

  function t(key: string): string {
    const keys = key.split('.');
    let value: any = translations;
    for (const k of keys) {
      value = value?.[k];
    }
    return value || key;
  }

  function base64UrlDecode(str: string): string {
    // 添加 padding 如果需要
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    try {
      return decodeURIComponent(escape(atob(base64)));
    } catch (e) {
      throw new Error('Invalid base64url encoding');
    }
  }

  function decodeJWT() {
    error = '';
    decodedHeader = '';
    decodedPayload = '';
    signature = '';

    if (!jwtToken.trim()) {
      return;
    }

    try {
      // 移除可能的 Bearer 前缀
      let token = jwtToken.trim();
      if (token.startsWith('Bearer ') || token.startsWith('bearer ')) {
        token = token.substring(7).trim();
      }

      // 分割 JWT 的三个部分
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format. JWT should have three parts separated by dots.');
      }

      const [headerPart, payloadPart, signaturePart] = parts;

      // 解码 Header
      try {
        const headerJson = base64UrlDecode(headerPart);
        const headerObj = JSON.parse(headerJson);
        decodedHeader = JSON.stringify(headerObj, null, 2);
      } catch (e) {
        throw new Error(`Failed to decode header: ${e instanceof Error ? e.message : 'Unknown error'}`);
      }

      // 解码 Payload
      try {
        const payloadJson = base64UrlDecode(payloadPart);
        const payloadObj = JSON.parse(payloadJson);
        
        // 格式化日期字段（如果存在）
        if (payloadObj.exp) {
          payloadObj.exp_formatted = new Date(payloadObj.exp * 1000).toISOString();
        }
        if (payloadObj.iat) {
          payloadObj.iat_formatted = new Date(payloadObj.iat * 1000).toISOString();
        }
        if (payloadObj.nbf) {
          payloadObj.nbf_formatted = new Date(payloadObj.nbf * 1000).toISOString();
        }
        
        decodedPayload = JSON.stringify(payloadObj, null, 2);
      } catch (e) {
        throw new Error(`Failed to decode payload: ${e instanceof Error ? e.message : 'Unknown error'}`);
      }

      // 保存签名（不解码，因为它是签名的哈希值）
      signature = signaturePart;

    } catch (err) {
      error = err instanceof Error ? err.message : 'Unknown error occurred';
    }
  }

  async function copyToClipboard(text: string, type: 'header' | 'payload' | 'signature') {
    if (!text) return;
    
    try {
      await navigator.clipboard.writeText(text);
      copied = { ...copied, [type]: true };
      setTimeout(() => {
        copied = { ...copied, [type]: false };
      }, 2000);
    } catch (error) {
      console.error('Failed to copy:', error);
    }
  }

  function clear() {
    jwtToken = '';
    decodedHeader = '';
    decodedPayload = '';
    signature = '';
    error = '';
    copied = { header: false, payload: false, signature: false };
  }

  // 自动解码
  $effect(() => {
    if (jwtToken.trim()) {
      decodeJWT();
    } else {
      decodedHeader = '';
      decodedPayload = '';
      signature = '';
      error = '';
    }
  });
</script>

<div class="w-full ml-0 mr-0 p-2 flex flex-col h-[calc(100vh-2rem)]">
  <!-- 输入区域 -->
  <div class="card flex-shrink-0 mb-4">
    <div class="space-y-4">
      <div>
        <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          {t('jwt.input')}
        </label>
        <textarea
          bind:value={jwtToken}
          placeholder={t('jwt.placeholder')}
          class="textarea font-mono text-sm min-h-[120px]"
        ></textarea>
      </div>

      <div class="flex gap-2">
        <button
          onclick={decodeJWT}
          class="btn-secondary"
        >
          {t('jwt.decode')}
        </button>
        <button
          onclick={clear}
          class="btn-secondary"
        >
          <Trash2 class="w-4 h-4 inline mr-1" />
          {t('common.clear')}
        </button>
      </div>

      {#if error}
        <div class="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <p class="text-sm text-red-800 dark:text-red-200">{error}</p>
        </div>
      {/if}
    </div>
  </div>

  <!-- 解码结果 -->
  {#if decodedHeader || decodedPayload || signature}
    <div class="grid grid-cols-1 md:grid-cols-3 gap-3 flex-1 min-h-0">
      <!-- Header -->
      <div class="card flex flex-col h-full">
        <div class="flex items-center justify-between mb-2 flex-shrink-0">
          <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">
            {t('jwt.header')}
          </h3>
          {#if decodedHeader}
            <button
              onclick={() => copyToClipboard(decodedHeader, 'header')}
              class="btn-secondary text-sm transition-all duration-200 {copied.header ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
            >
              {#if copied.header}
                <Check class="w-4 h-4 inline mr-1" />
                {t('common.copied')}
              {:else}
                <Copy class="w-4 h-4 inline mr-1" />
                {t('common.copy')}
              {/if}
            </button>
          {/if}
        </div>
        <div class="flex-1 flex flex-col min-h-0">
          {#if decodedHeader}
            <textarea
              value={decodedHeader}
              readonly
              class="textarea font-mono text-sm flex-1 resize-none overflow-y-auto {copied.header ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
            ></textarea>
          {:else}
            <div class="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 flex-1 flex items-center justify-center min-h-[150px]">
              <span class="text-sm text-gray-400 dark:text-gray-500">{t('jwt.noHeader')}</span>
            </div>
          {/if}
        </div>
      </div>

      <!-- Payload -->
      <div class="card flex flex-col h-full">
        <div class="flex items-center justify-between mb-2 flex-shrink-0">
          <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">
            {t('jwt.payload')}
          </h3>
          {#if decodedPayload}
            <button
              onclick={() => copyToClipboard(decodedPayload, 'payload')}
              class="btn-secondary text-sm transition-all duration-200 {copied.payload ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
            >
              {#if copied.payload}
                <Check class="w-4 h-4 inline mr-1" />
                {t('common.copied')}
              {:else}
                <Copy class="w-4 h-4 inline mr-1" />
                {t('common.copy')}
              {/if}
            </button>
          {/if}
        </div>
        <div class="flex-1 flex flex-col min-h-0">
          {#if decodedPayload}
            <textarea
              value={decodedPayload}
              readonly
              class="textarea font-mono text-sm flex-1 resize-none overflow-y-auto {copied.payload ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700' : ''} transition-colors duration-300"
            ></textarea>
          {:else}
            <div class="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 flex-1 flex items-center justify-center min-h-[150px]">
              <span class="text-sm text-gray-400 dark:text-gray-500">{t('jwt.noPayload')}</span>
            </div>
          {/if}
        </div>
      </div>

      <!-- Signature -->
      <div class="card flex flex-col h-full">
        <div class="flex items-center justify-between mb-2 flex-shrink-0">
          <h3 class="text-base font-semibold text-gray-900 dark:text-gray-100">
            {t('jwt.signature')}
          </h3>
          {#if signature}
            <button
              onclick={() => copyToClipboard(signature, 'signature')}
              class="btn-secondary text-sm transition-all duration-200 {copied.signature ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
            >
              {#if copied.signature}
                <Check class="w-4 h-4 inline mr-1" />
                {t('common.copied')}
              {:else}
                <Copy class="w-4 h-4 inline mr-1" />
                {t('common.copy')}
              {/if}
            </button>
          {/if}
        </div>
        <div class="flex-1 flex flex-col min-h-0">
          {#if signature}
            <div class="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 flex-1 flex flex-col overflow-y-auto min-h-[150px]">
              <code class="text-sm font-mono text-gray-900 dark:text-gray-100 break-all">
                {signature}
              </code>
              <p class="text-xs text-gray-500 dark:text-gray-400 mt-1.5">
                {t('jwt.signatureHint')}
              </p>
            </div>
          {:else}
            <div class="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 flex-1 flex items-center justify-center min-h-[150px]">
              <span class="text-sm text-gray-400 dark:text-gray-500">{t('jwt.noSignature')}</span>
            </div>
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>

