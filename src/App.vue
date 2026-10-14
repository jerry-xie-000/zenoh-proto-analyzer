<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { listen } from '@tauri-apps/api/event'
import Toolbar from './components/Toolbar.vue'
import CaptureBar from './components/CaptureBar.vue'
import PacketTable from './components/PacketTable.vue'
import SplitPane from './components/SplitPane.vue'
import DetailPanel from './components/DetailPanel.vue'
import StatsDialog from './components/StatsDialog.vue'
import { useAnalyzerStore } from './stores/analyzer'

const store = useAnalyzerStore()
const showStats = ref(false)
const split = ref<InstanceType<typeof SplitPane> | null>(null)

// Esc 退出最大化
onMounted(() => {
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && split.value?.maximized) split.value.toggleMax()
  })
  // 命令行参数自动打开：app.exe <pcap> <proto目录>
  listen<[string, string]>('demo-open', (e) => {
    store.protoDir = e.payload[1]
    store.openPcap(e.payload[0])
  })
})
</script>

<template>
  <div class="h-full flex flex-col">
    <Toolbar v-model:show-stats="showStats" />
    <CaptureBar />

    <div class="flex-1 min-h-0">
      <SplitPane ref="split" :initial="0.58">
        <template #left>
          <PacketTable />
        </template>
        <template #right>
          <DetailPanel @toggle-max="split?.toggleMax()" />
        </template>
      </SplitPane>
    </div>

    <!-- 底部状态栏 -->
    <div
      class="flex items-center gap-4 h-6 px-3 border-t border-border-dim bg-bg-panel text-[11px] text-text-dim shrink-0"
    >
      <span v-if="store.fileName">{{ store.fileName }}</span>
      <span v-if="store.rows.length">共 {{ store.rows.length }} 条</span>
      <span v-if="store.filteredRows.length !== store.rows.length">
        过滤后 {{ store.filteredRows.length }} 条
      </span>
      <span v-if="store.mode === 'live' && store.capturing" class="text-green">● 捕获中</span>
      <div class="flex-1" />
      <span class="truncate max-w-[40%]" :title="store.protoDir">proto: {{ store.protoDir || '未设置' }}</span>
    </div>

    <StatsDialog v-model:show="showStats" />
  </div>
</template>
