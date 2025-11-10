<script lang="ts">
  import { translationsStore } from '$lib/stores/i18n';
  import { Copy, Check, Trash2, FileImage, FileText, GitBranch, Download } from 'lucide-svelte';
  import { marked, type RendererObject } from 'marked';
  import mermaid from 'mermaid';
  import { onMount } from 'svelte';
  import html2canvas from 'html2canvas';
  import { browser } from '$app/environment';
  
  // 动态导入 Tauri 插件（仅在需要时加载）
  let dialogModule: typeof import('@tauri-apps/plugin-dialog') | null = null;
  let fsModule: typeof import('@tauri-apps/plugin-fs') | null = null;

  let activeView = $state<'svg' | 'markdown' | 'mermaid'>('svg');
  let svgContent = $state('');
  let markdownContent = $state('');
  let mermaidContent = $state('');
  let copied = $state<{ svg: boolean; markdown: boolean; preview: boolean; mermaid: boolean }>({ svg: false, markdown: false, preview: false, mermaid: false });
  let previewElement = $state<HTMLDivElement | null>(null);
  let svgFileInput = $state<HTMLInputElement | null>(null);
  let markdownFileInput = $state<HTMLInputElement | null>(null);
  let mermaidFileInput = $state<HTMLInputElement | null>(null);
  let mermaidContainer = $state<HTMLDivElement | null>(null);

  let translations = $derived($translationsStore);

  function t(key: string): string {
    const keys = key.split('.');
    let value: any = translations;
    for (const k of keys) {
      value = value?.[k];
    }
    return value || key;
  }

  async function copyToClipboard(text: string, type: 'svg' | 'markdown' | 'preview') {
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

  async function copyPreviewContent() {
    if (!markdownContent.trim() || !previewElement) return;
    // 从预览 DOM 元素中提取纯文本内容
    const text = previewElement.innerText || previewElement.textContent || '';
    await copyToClipboard(text, 'preview');
  }

  function clear() {
    if (activeView === 'svg') {
      svgContent = '';
      if (svgFileInput) {
        svgFileInput.value = '';
      }
    } else if (activeView === 'markdown') {
      markdownContent = '';
      if (markdownFileInput) {
        markdownFileInput.value = '';
      }
    } else if (activeView === 'mermaid') {
      mermaidContent = '';
      if (mermaidFileInput) {
        mermaidFileInput.value = '';
      }
      if (mermaidContainer) {
        mermaidContainer.innerHTML = '';
      }
    }
    copied = { svg: false, markdown: false, preview: false, mermaid: false };
  }

  async function handleSvgFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;

    // 检查文件大小（限制为 10MB）
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      alert(`File size exceeds 10MB limit. Please select a smaller file.`);
      target.value = '';
      return;
    }

    // 检查文件类型
    if (!file.type.includes('svg') && !file.name.toLowerCase().endsWith('.svg')) {
      alert('Please select an SVG file.');
      target.value = '';
      return;
    }

    try {
      const text = await file.text();
      svgContent = text;
    } catch (error) {
      console.error('Failed to read file:', error);
      alert('Failed to read file. Please try again.');
      target.value = '';
    }
  }

  async function handleMarkdownFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;

    // 检查文件大小（限制为 10MB）
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      alert(`File size exceeds 10MB limit. Please select a smaller file.`);
      target.value = '';
      return;
    }

    // 检查文件类型
    const validExtensions = ['.md', '.markdown', '.txt'];
    const fileName = file.name.toLowerCase();
    const isValidType = validExtensions.some(ext => fileName.endsWith(ext)) || 
                        file.type.includes('markdown') || 
                        file.type === 'text/plain';
    
    if (!isValidType) {
      alert('Please select a Markdown file (.md, .markdown, or .txt).');
      target.value = '';
      return;
    }

    try {
      const text = await file.text();
      markdownContent = text;
    } catch (error) {
      console.error('Failed to read file:', error);
      alert('Failed to read file. Please try again.');
      target.value = '';
    }
  }

  async function handleMermaidFileSelect(event: Event) {
    const target = event.target as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;

    // 检查文件大小（限制为 10MB）
    const maxSize = 10 * 1024 * 1024; // 10MB
    if (file.size > maxSize) {
      alert(`File size exceeds 10MB limit. Please select a smaller file.`);
      target.value = '';
      return;
    }

    // 检查文件类型
    const validExtensions = ['.mmd', '.mermaid', '.md', '.txt'];
    const fileName = file.name.toLowerCase();
    const isValidType = validExtensions.some(ext => fileName.endsWith(ext)) || 
                        file.type === 'text/plain';
    
    if (!isValidType) {
      alert('Please select a Mermaid file (.mmd, .mermaid, .md, or .txt).');
      target.value = '';
      return;
    }

    try {
      const text = await file.text();
      mermaidContent = text;
      await renderMermaid();
    } catch (error) {
      console.error('Failed to read file:', error);
      alert('Failed to read file. Please try again.');
      target.value = '';
    }
  }

  async function renderMermaid() {
    if (!mermaidContainer || !mermaidContent.trim()) {
      return;
    }

    try {
      // 清空容器
      mermaidContainer.innerHTML = '';
      
      // 生成唯一 ID
      const id = `mermaid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      
      // 创建临时元素用于渲染
      const tempDiv = document.createElement('div');
      tempDiv.className = 'mermaid';
      tempDiv.id = id;
      tempDiv.textContent = mermaidContent;
      mermaidContainer.appendChild(tempDiv);
      
      // 使用 mermaid.run() 渲染图表（mermaid 11.x API）
      await mermaid.run({
        nodes: [tempDiv]
      });
    } catch (error) {
      console.error('Mermaid rendering error:', error);
      if (mermaidContainer) {
        mermaidContainer.innerHTML = `<div class="text-center text-red-600 dark:text-red-400 p-4">
          <p class="text-sm">Error rendering Mermaid diagram</p>
          <p class="text-xs mt-2">${error instanceof Error ? error.message : 'Unknown error'}</p>
        </div>`;
      }
    }
  }

  // 监听 mermaidContent 变化并重新渲染
  $effect(() => {
    if (activeView === 'mermaid' && mermaidContent.trim()) {
      renderMermaid();
    }
  });

  // 导出预览结果为图片
  async function exportPreviewAsImage() {
    let elementToExport: HTMLElement | null = null;
    let filename = 'preview';

    if (activeView === 'svg') {
      // SVG 预览：查找预览容器中的 SVG 元素
      const previewCard = document.querySelector('[data-preview="svg"]');
      if (previewCard) {
        const svgContainer = previewCard.querySelector('.border') as HTMLElement;
        if (svgContainer && svgContainer.querySelector('svg')) {
          elementToExport = svgContainer;
          filename = 'svg-preview';
        }
      }
    } else if (activeView === 'mermaid') {
      // Mermaid 预览：导出 Mermaid 容器
      // Mermaid 渲染后，.mermaid 元素会被转换为 SVG，所以检查 SVG 或 .mermaid
      if (mermaidContainer && (mermaidContainer.querySelector('svg') || mermaidContainer.querySelector('.mermaid'))) {
        elementToExport = mermaidContainer;
        filename = 'mermaid-preview';
      }
    }

    if (!elementToExport) {
      alert('No preview content to export.');
      return;
    }

    try {
      // 使用 html2canvas 将元素转换为 canvas
      const canvas = await html2canvas(elementToExport, {
        backgroundColor: '#ffffff', // 白色背景
        scale: 2, // 提高分辨率
        useCORS: true,
        logging: false,
        allowTaint: true
      });

      // 检查是否在 Tauri 环境中
      const isTauri = browser && typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

      if (isTauri) {
        // Tauri 环境：使用 dialog 和 fs API
        try {
          // 确保模块已加载
          if (!dialogModule) {
            dialogModule = await import('@tauri-apps/plugin-dialog');
          }
          if (!fsModule) {
            fsModule = await import('@tauri-apps/plugin-fs');
          }

          if (!dialogModule || !fsModule) {
            throw new Error('Failed to load Tauri plugins');
          }

          // 打开保存对话框
          // Tauri 2.0 插件使用命名导出
          const { save } = dialogModule;
          if (!save || typeof save !== 'function') {
            throw new Error('save function not found in dialog module');
          }
          
          const filePath = await save({
            defaultPath: `${filename}-${Date.now()}.png`,
            filters: [{
              name: 'PNG Image',
              extensions: ['png']
            }]
          });

          if (!filePath) {
            // 用户取消了保存对话框
            return;
          }

          // 将 canvas 转换为 blob，然后转换为 Uint8Array
          // 使用 Promise 包装 toBlob 以确保异步操作完成，并添加超时处理
          await new Promise<void>((resolve, reject) => {
            // 设置超时（10秒）
            const timeout = setTimeout(() => {
              reject(new Error('Timeout: Failed to generate image blob within 10 seconds.'));
            }, 10000);

            try {
              canvas.toBlob(async (blob) => {
                clearTimeout(timeout);
                
                try {
                  if (!blob) {
                    reject(new Error('Failed to generate image blob: blob is null.'));
                    return;
                  }

                  console.log('Image blob generated, size:', blob.size);

                  const arrayBuffer = await blob.arrayBuffer();
                  const uint8Array = new Uint8Array(arrayBuffer);

                  console.log('Writing file to:', filePath);
                  
                  // 写入文件 - Tauri 2.0 插件使用 writeFile（不是 writeBinaryFile）
                  const { writeFile } = fsModule;
                  if (!writeFile || typeof writeFile !== 'function') {
                    throw new Error('writeFile function not found in fs module');
                  }
                  
                  await writeFile(filePath, uint8Array);
                  
                  console.log('File saved successfully');
                  resolve();
                } catch (error) {
                  console.error('Error in toBlob callback:', error);
                  reject(error);
                }
              }, 'image/png');

              // 如果 canvas.toBlob 立即失败（某些浏览器可能不支持）
              if (typeof canvas.toBlob !== 'function') {
                clearTimeout(timeout);
                reject(new Error('canvas.toBlob is not supported'));
              }
            } catch (error) {
              clearTimeout(timeout);
              reject(error);
            }
          });
        } catch (error) {
          console.error('Tauri export error:', error);
          const errorMessage = error instanceof Error ? error.message : String(error);
          console.error('Error details:', {
            error,
            dialogModule: !!dialogModule,
            fsModule: !!fsModule,
            canvas: !!canvas,
            canvasWidth: canvas?.width,
            canvasHeight: canvas?.height
          });
          alert(`Failed to export image: ${errorMessage}`);
        }
      } else {
        // 浏览器环境：使用下载链接
        canvas.toBlob((blob) => {
          if (!blob) {
            alert('Failed to generate image.');
            return;
          }

          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = `${filename}-${Date.now()}.png`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          URL.revokeObjectURL(url);
        }, 'image/png');
      }
    } catch (error) {
      console.error('Export error:', error);
      alert('Failed to export image. Please try again.');
    }
  }

  // 初始化 Mermaid 和预加载 Tauri 插件
  onMount(() => {
    mermaid.initialize({ 
      startOnLoad: false,
      theme: 'default',
      securityLevel: 'loose',
      fontFamily: 'inherit'
    });
    
    // 预加载 Tauri 插件（如果可用）
    if (browser && typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window) {
      import('@tauri-apps/plugin-dialog').then(module => {
        dialogModule = module;
      }).catch(() => {});
      import('@tauri-apps/plugin-fs').then(module => {
        fsModule = module;
      }).catch(() => {});
    }
  });

  // 检查 SVG 内容是否有效
  function isValidSVG(content: string): boolean {
    if (!content.trim()) return false;
    try {
      // 简单的 SVG 验证：检查是否包含 SVG 标签
      const parser = new DOMParser();
      const doc = parser.parseFromString(content, 'image/svg+xml');
      const parseError = doc.querySelector('parsererror');
      return !parseError && doc.querySelector('svg') !== null;
    } catch {
      return false;
    }
  }

  // 配置 marked 选项并自定义渲染器
  const customRenderer: Partial<RendererObject> = {
    link(href: string, title: string | null | undefined, text: string) {
      return `<a href="${href}" target="_blank" rel="noopener noreferrer"${title ? ` title="${title}"` : ''}>${text}</a>`;
    },
    image(href: string, title: string | null | undefined, text: string) {
      return `<img src="${href}" alt="${text}" class="max-w-full rounded"${title ? ` title="${title}"` : ''}>`;
    },
  };

  marked.use({
    breaks: true, // 支持换行符（单个换行符转换为 <br>）
    gfm: true, // 启用 GitHub Flavored Markdown
    renderer: customRenderer,
  });

  // 渲染 Markdown
  function renderMarkdown(content: string): string {
    if (!content.trim()) return '';
    
    try {
      return marked.parse(content) as string;
    } catch (error) {
      console.error('Markdown parsing error:', error);
      return `<p class="text-red-600 dark:text-red-400">Error parsing Markdown: ${error}</p>`;
    }
  }
</script>

<div class="w-full ml-0 mr-0 p-2 flex flex-col h-[calc(100vh-2rem)]">
  <!-- 标签页导航 -->
  <div class="card p-0 mb-4 flex-shrink-0">
    <div class="flex items-center border-b border-gray-200 dark:border-gray-700">
      <button
        onclick={() => activeView = 'svg'}
        class="flex items-center gap-2 px-4 py-3 border-b-2 transition-colors {activeView === 'svg'
          ? 'border-primary-600 dark:border-primary-400 text-primary-600 dark:text-primary-400 bg-gray-50 dark:bg-gray-800'
          : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800'}"
      >
        <FileImage class="w-4 h-4" />
        <span class="text-sm font-medium">{t('previewer.svg')}</span>
      </button>
      <button
        onclick={() => activeView = 'markdown'}
        class="flex items-center gap-2 px-4 py-3 border-b-2 transition-colors {activeView === 'markdown'
          ? 'border-primary-600 dark:border-primary-400 text-primary-600 dark:text-primary-400 bg-gray-50 dark:bg-gray-800'
          : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800'}"
      >
        <FileText class="w-4 h-4" />
        <span class="text-sm font-medium">{t('previewer.markdown')}</span>
      </button>
      <button
        onclick={() => activeView = 'mermaid'}
        class="flex items-center gap-2 px-4 py-3 border-b-2 transition-colors {activeView === 'mermaid'
          ? 'border-primary-600 dark:border-primary-400 text-primary-600 dark:text-primary-400 bg-gray-50 dark:bg-gray-800'
          : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800'}"
      >
        <GitBranch class="w-4 h-4" />
        <span class="text-sm font-medium">{t('previewer.mermaid')}</span>
      </button>
    </div>
  </div>

  <!-- 内容区域 -->
  <div class="flex-1 min-h-0 flex flex-col">
    {#if activeView === 'svg'}
      <!-- SVG Preview - 左右布局 -->
      <div class="flex-1 min-h-0 flex flex-col">
        <div class="flex items-center justify-between mb-2 flex-shrink-0">
          <div class="flex items-center gap-4">
            <input
              type="file"
              accept=".svg,image/svg+xml"
              onchange={handleSvgFileSelect}
              bind:this={svgFileInput}
              class="hidden"
              id="svg-file-input"
            />
            <label
              for="svg-file-input"
              class="btn-secondary cursor-pointer flex items-center text-sm"
            >
              <FileImage class="w-4 h-4 inline mr-1" />
              {t('previewer.selectFile')}
            </label>
            <button
              onclick={() => copyToClipboard(svgContent, 'svg')}
              class="btn-secondary text-sm transition-all duration-200 {copied.svg ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
            >
              {#if copied.svg}
                <Check class="w-4 h-4 inline mr-1" />
                {t('common.copied')}
              {:else}
                <Copy class="w-4 h-4 inline mr-1" />
                {t('common.copy')}
              {/if}
            </button>
          </div>
          <div class="flex items-center gap-2">
            <button
              onclick={exportPreviewAsImage}
              class="btn-secondary text-sm"
              disabled={!svgContent.trim() || !isValidSVG(svgContent)}
            >
              <Download class="w-4 h-4 inline mr-1" />
              {t('previewer.exportImage')}
            </button>
            <button
              onclick={clear}
              class="btn-secondary text-sm"
            >
              <Trash2 class="w-4 h-4 inline mr-1" />
              {t('common.clear')}
            </button>
          </div>
        </div>
        
        <div class="flex-1 min-h-0 grid grid-cols-2 gap-2">
          <!-- SVG 输入 -->
          <div class="card flex flex-col h-full">
            <div class="flex items-center justify-between mb-2 flex-shrink-0">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('previewer.svgInput')}
              </span>
            </div>
            <div class="flex-1 min-h-0">
              <textarea
                bind:value={svgContent}
                placeholder={t('previewer.svgPlaceholder')}
                class="textarea font-mono text-sm h-full resize-none"
              ></textarea>
            </div>
          </div>

          <!-- SVG 预览 -->
          <div class="card flex flex-col h-full" data-preview="svg">
            <div class="flex items-center justify-between mb-2 flex-shrink-0">
              <h3 class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('previewer.preview')}
              </h3>
              {#if svgContent.trim() && !isValidSVG(svgContent)}
                <span class="text-xs text-red-600 dark:text-red-400">
                  {t('previewer.invalidSVG')}
                </span>
              {/if}
            </div>
            <div class="flex-1 border border-gray-300 dark:border-gray-600 rounded-lg overflow-auto bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4 min-h-0">
              {#if svgContent.trim()}
                {#if isValidSVG(svgContent)}
                  <div class="max-w-full max-h-full">
                    {@html svgContent}
                  </div>
                {:else}
                  <div class="text-center text-gray-400 dark:text-gray-500">
                    <p class="text-sm">{t('previewer.invalidSVGMessage')}</p>
                  </div>
                {/if}
              {:else}
                <div class="text-center text-gray-400 dark:text-gray-500 text-sm">
                  {t('previewer.svgPlaceholder')}
                </div>
              {/if}
            </div>
          </div>
        </div>
      </div>
    {:else if activeView === 'markdown'}
      <!-- Markdown Preview - 左右布局 -->
      <div class="flex-1 min-h-0 flex flex-col">
        <div class="flex items-center justify-between mb-2 flex-shrink-0">
          <div class="flex items-center gap-4">
            <input
              type="file"
              accept=".md,.markdown,.txt,text/markdown,text/plain"
              onchange={handleMarkdownFileSelect}
              bind:this={markdownFileInput}
              class="hidden"
              id="markdown-file-input"
            />
            <label
              for="markdown-file-input"
              class="btn-secondary cursor-pointer flex items-center text-sm"
            >
              <FileText class="w-4 h-4 inline mr-1" />
              {t('previewer.selectFile')}
            </label>
            <button
              onclick={clear}
              class="btn-secondary text-sm"
            >
              <Trash2 class="w-4 h-4 inline mr-1" />
              {t('common.clear')}
            </button>
          </div>
          <button
            onclick={copyPreviewContent}
            class="btn-secondary text-sm transition-all duration-200 {copied.preview ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
            disabled={!markdownContent.trim()}
          >
            {#if copied.preview}
              <Check class="w-4 h-4 inline mr-1" />
              {t('common.copied')}
            {:else}
              <Copy class="w-4 h-4 inline mr-1" />
              {t('common.copy')}
            {/if}
          </button>
        </div>
        
        <div class="flex-1 min-h-0 grid grid-cols-2 gap-2">
          <!-- Markdown 输入 -->
          <div class="card flex flex-col h-full">
            <div class="flex items-center justify-between mb-2 flex-shrink-0">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('previewer.markdownInput')}
              </span>
            </div>
            <div class="flex-1 min-h-0">
              <textarea
                bind:value={markdownContent}
                placeholder={t('previewer.markdownPlaceholder')}
                class="textarea font-mono text-sm h-full resize-none"
              ></textarea>
            </div>
          </div>

          <!-- Markdown 预览 -->
          <div class="card flex flex-col h-full">
            <div class="flex items-center justify-between mb-2 flex-shrink-0">
              <h3 class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('previewer.preview')}
              </h3>
            </div>
            <div class="flex-1 border border-gray-300 dark:border-gray-600 rounded-lg overflow-auto bg-white dark:bg-gray-800 p-6 min-h-0">
              {#if markdownContent.trim()}
                <div class="markdown-content" bind:this={previewElement}>
                  {@html renderMarkdown(markdownContent)}
                </div>
              {:else}
                <div class="flex items-center justify-center h-full text-gray-400 dark:text-gray-500 text-sm">
                  {t('previewer.markdownPlaceholder')}
                </div>
              {/if}
            </div>
          </div>
        </div>
      </div>
    {:else if activeView === 'mermaid'}
      <!-- Mermaid Preview - 左右布局 -->
      <div class="flex-1 min-h-0 flex flex-col">
        <div class="flex items-center justify-between mb-2 flex-shrink-0">
          <div class="flex items-center gap-4">
            <input
              type="file"
              accept=".mmd,.mermaid,.md,.txt,text/plain"
              onchange={handleMermaidFileSelect}
              bind:this={mermaidFileInput}
              class="hidden"
              id="mermaid-file-input"
            />
            <label
              for="mermaid-file-input"
              class="btn-secondary cursor-pointer flex items-center text-sm"
            >
              <GitBranch class="w-4 h-4 inline mr-1" />
              {t('previewer.selectFile')}
            </label>
            <button
              onclick={() => copyToClipboard(mermaidContent, 'mermaid')}
              class="btn-secondary text-sm transition-all duration-200 {copied.mermaid ? 'bg-green-500 hover:bg-green-600 text-white' : ''}"
            >
              {#if copied.mermaid}
                <Check class="w-4 h-4 inline mr-1" />
                {t('common.copied')}
              {:else}
                <Copy class="w-4 h-4 inline mr-1" />
                {t('common.copy')}
              {/if}
            </button>
          </div>
          <div class="flex items-center gap-2">
            <button
              onclick={exportPreviewAsImage}
              class="btn-secondary text-sm"
              disabled={!mermaidContent.trim()}
            >
              <Download class="w-4 h-4 inline mr-1" />
              {t('previewer.exportImage')}
            </button>
            <button
              onclick={clear}
              class="btn-secondary text-sm"
            >
              <Trash2 class="w-4 h-4 inline mr-1" />
              {t('common.clear')}
            </button>
          </div>
        </div>
        
        <div class="flex-1 min-h-0 grid grid-cols-2 gap-2">
          <!-- Mermaid 输入 -->
          <div class="card flex flex-col h-full">
            <div class="flex items-center justify-between mb-2 flex-shrink-0">
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('previewer.mermaidInput')}
              </span>
            </div>
            <div class="flex-1 min-h-0">
              <textarea
                bind:value={mermaidContent}
                placeholder={t('previewer.mermaidPlaceholder')}
                class="textarea font-mono text-sm h-full resize-none"
              ></textarea>
            </div>
          </div>

          <!-- Mermaid 预览 -->
          <div class="card flex flex-col h-full">
            <div class="flex items-center justify-between mb-2 flex-shrink-0">
              <h3 class="text-sm font-medium text-gray-700 dark:text-gray-300">
                {t('previewer.preview')}
              </h3>
            </div>
            <div class="flex-1 border border-gray-300 dark:border-gray-600 rounded-lg overflow-auto bg-white dark:bg-gray-800 p-6 min-h-0" bind:this={mermaidContainer}>
              {#if !mermaidContent.trim()}
                <div class="flex items-center justify-center h-full text-gray-400 dark:text-gray-500 text-sm">
                  {t('previewer.mermaidPlaceholder')}
                </div>
              {/if}
            </div>
          </div>
        </div>
      </div>
    {/if}
  </div>
</div>

