<script setup lang="ts">
import { ref, watch } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-dialog'
import {
  ChartColumn,
  FileArchive,
  FolderOpen,
  Search,
  Trash2,
  X,
} from 'lucide-vue-next'
import { useAnalyzerStore } from '../stores/analyzer'

const store = useAnalyzerStore()

const showStats = defineModel<boolean>('showStats')

async function pickPcap() {
  const path = await open({
    title: '打开 pcapng / pcap 抓包文件',
    filters: [{ name: '抓包文件', extensions: ['pcapng', 'pcap', 'cap'] }],
  })
  if (typeof path === 'string') await store.openPcap(path)
}

async function pickProtoDir() {
  const dir = await open({ title: '选择 proto 定义根目录', directory: true })
  if (typeof dir === 'string') {
    store.protoDir = dir
    await store.reparseWithProto()
  }
}

async function clearProtoDir() {
  store.protoDir = ''
  await store.reparseWithProto()
}

const protoFiles = ref(0)
async function countProto() {
  if (!store.protoDir) {
    protoFiles.value = 0
    return
  }
  try {
    protoFiles.value = await invoke<number>('count_proto_files', { dir: store.protoDir })
  } catch {
    protoFiles.value = 0
  }
}
watch(() => store.protoDir, countProto, { immediate: true })
</script>

<template>
  <div class="flex items-center gap-2 px-3 h-11 border-b border-border-dim bg-bg-panel shrink-0">
    <button
      class="btn"
      :disabled="store.loading || store.capturing"
      title="打开 pcapng / pcap 文件"
      @click="pickPcap"
    >
      <FolderOpen :size="15" /> 打开抓包
    </button>

    <div class="flex items-center gap-1">
      <button
        class="btn"
        :class="{ 'border-accent text-accent': store.protoDir }"
        :disabled="store.capturing"
        title="选择 proto 定义根目录（包含 .proto 文件，import 相对此目录）"
        @click="pickProtoDir"
      >
        <FileArchive :size="15" />
        Proto
        <span v-if="protoFiles" class="text-text-dim font-normal">({{ protoFiles }} 个)</span>
      </button>
      <button
        v-if="store.protoDir"
        class="p-1 text-text-dim hover:text-red"
        title="清除 proto 目录"
        @click="clearProtoDir"
      >
        <X :size="13" />
      </button>
    </div>

    <div class="flex-1" />

    <div class="relative">
      <Search :size="14" class="absolute left-2 top-1/2 -translate-y-1/2 text-text-dim" />
      <input
        v-model="store.filterText"
        class="input w-64 pl-7"
        placeholder="过滤 topic / 类型 / 设备 / IP…"
      />
      <button
        v-if="store.filterText"
        class="absolute right-2 top-1/2 -translate-y-1/2 text-text-dim hover:text-text-main"
        @click="store.filterText = ''"
      >
        <X :size="13" />
      </button>
    </div>

    <select v-model="store.filterType" class="input w-44">
      <option v-for="t in store.typeOptions" :key="t" :value="t">{{ t }}</option>
    </select>

    <label class="flex items-center gap-1 text-[12px] text-text-dim cursor-pointer select-none">
      <input v-model="store.filterIncomplete" type="checkbox" class="accent-accent" />
      仅未解析topic
    </label>

    <button class="btn" :disabled="!store.stats" title="统计面板" @click="showStats = true">
      <ChartColumn :size="15" /> 统计
    </button>

    <button class="btn text-red hover:border-red" :disabled="store.rows.length === 0" title="清空数据" @click="store.clearData()">
      <Trash2 :size="15" />
    </button>
  </div>

  <div
    v-if="store.error"
    class="flex items-center gap-2 px-3 py-1.5 bg-red/10 border-b border-red/40 text-red text-[12px]"
  >
    <span class="flex-1">{{ store.error }}</span>
    <button class="text-text-dim hover:text-text-main" @click="store.error = null"><X :size="13" /></button>
  </div>
</template>
