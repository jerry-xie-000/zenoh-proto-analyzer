<script setup lang="ts">
import { onMounted } from 'vue'
import { CirclePause, CirclePlay, CircleStop, Eye, Radio } from 'lucide-vue-next'
import { useAnalyzerStore } from '../stores/analyzer'

const store = useAnalyzerStore()
onMounted(() => store.loadInterfaces())
</script>

<template>
  <div
    class="flex items-center gap-2 px-3 h-10 border-b border-border-dim bg-bg-panel/60 shrink-0"
  >
    <Radio :size="14" class="text-orange" />
    <select v-model="store.selectedInterface" class="input w-80" :disabled="store.capturing">
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

    <button v-if="!store.capturing" class="btn text-green hover:border-green" @click="store.startCapture()">
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
</template>
