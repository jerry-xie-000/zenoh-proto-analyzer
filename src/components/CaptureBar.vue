<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { save } from '@tauri-apps/plugin-dialog'
import { CirclePause, CirclePlay, CircleStop, Eye, HardDriveDownload, Radio, X } from 'lucide-vue-next'
import { useAnalyzerStore } from '../stores/analyzer'

const store = useAnalyzerStore()
onMounted(() => store.loadInterfaces())

const SAVE_KEY = 'zenoh-analyzer.save-path'
const savePath = ref(localStorage.getItem(SAVE_KEY) ?? '')

async function pickSavePath() {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  const def = `zenoh-capture-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.pcapng`
  const path = await save({
    title: '保存捕获会话为 Wireshark 格式',
    defaultPath: def,
    filters: [{ name: 'pcapng', extensions: ['pcapng'] }],
  })
  savePath.value = typeof path === 'string' ? path : ''
  if (savePath.value) localStorage.setItem(SAVE_KEY, savePath.value)
}

function clearSavePath() {
  savePath.value = ''
  localStorage.removeItem(SAVE_KEY)
}

function startCapture() {
  store.startCapture(savePath.value || undefined)
}
</script>

<template>
  <div
    class="flex items-center gap-2 px-3 h-10 border-b border-border-dim bg-bg-panel/60 shrink-0"
  >
    <Radio :size="14" class="text-orange" />
    <select v-model="store.selectedInterface" class="input w-72" :disabled="store.capturing">
      <option v-for="i in store.interfaces" :key="i.name" :value="i.name" :title="`${i.name}\n${i.desc}`">
        {{ i.alias || i.desc || i.name }}{{ i.addresses.length ? ` (${i.addresses[0]})` : '' }}
      </option>
    </select>

    <input
      v-model="store.bpfFilter"
      class="input w-56 mono"
      placeholder="BPF 过滤器"
      :disabled="store.capturing"
    />

    <button
      class="btn"
      :class="{ 'border-accent text-accent': savePath }"
      :disabled="store.capturing"
      title="捕获时同步保存为 Wireshark 可打开的 pcapng 文件"
      @click="pickSavePath"
    >
      <HardDriveDownload :size="15" /> 保存到文件
    </button>
    <button
      v-if="savePath && !store.capturing"
      class="p-1 text-text-dim hover:text-red"
      title="清除保存路径"
      @click="clearSavePath"
    >
      <X :size="13" />
    </button>

    <button v-if="!store.capturing" class="btn text-green hover:border-green" @click="startCapture">
      <CirclePlay :size="15" /> 开始捕获
    </button>
    <button v-else class="btn text-red hover:border-red" @click="store.stopCapture()">
      <CircleStop :size="15" /> 停止
    </button>

    <button
      v-if="store.capturing"
      class="btn"
      :class="{ 'text-orange border-orange': store.paused }"
      @click="store.togglePause()"
    >
      <CirclePause :size="15" /> {{ store.paused ? `继续 (缓冲 ${store.pausedBuffer.length})` : '暂停显示' }}
    </button>

    <label
      v-if="store.capturing || store.mode === 'live'"
      class="flex items-center gap-1 text-[12px] text-text-dim cursor-pointer select-none"
    >
      <input v-model="store.follow" type="checkbox" class="accent-accent" />
      <Eye :size="13" /> 跟随最新
    </label>

    <div class="flex-1" />
    <div v-if="store.mode === 'live'" class="text-[12px] text-text-dim">
      共 <span class="text-accent mono">{{ store.rows.length }}</span> 条
    </div>
  </div>

  <div
    v-if="store.paused && store.pausedBuffer.length > 0"
    class="px-3 py-1 bg-orange/10 border-b border-orange/30 text-orange text-[12px]"
  >
    显示已暂停，后台缓冲 {{ store.pausedBuffer.length }} 条…
  </div>
  <div
    v-if="store.savedInfo"
    class="flex items-center gap-2 px-3 py-1 bg-green/10 border-b border-green/30 text-green text-[12px]"
  >
    ✓ 已保存 {{ store.savedInfo.frames }} 帧到 {{ store.savedInfo.path }}
  </div>
</template>
