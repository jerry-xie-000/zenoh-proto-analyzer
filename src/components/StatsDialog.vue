<script setup lang="ts">
import { X } from 'lucide-vue-next'
import { useAnalyzerStore } from '../stores/analyzer'

const store = useAnalyzerStore()
const show = defineModel<boolean>('show')

function fmtTime(ts: number | null): string {
  if (!ts) return '-'
  const d = new Date(ts / 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
</script>

<template>
  <div
    v-if="show && store.stats"
    class="fixed inset-0 z-50 bg-black/60 flex items-center justify-center"
    @click.self="show = false"
  >
    <div class="w-[720px] max-h-[80vh] bg-bg-panel border border-border-dim rounded-lg shadow-2xl flex flex-col">
      <div class="flex items-center px-4 h-11 border-b border-border-dim">
        <span class="font-medium">捕获统计</span>
        <div class="flex-1" />
        <button class="text-text-dim hover:text-text-main" @click="show = false"><X :size="16" /></button>
      </div>

      <div class="p-4 overflow-auto space-y-4 text-[13px]">
        <div class="grid grid-cols-3 gap-3">
          <div class="card"><div class="label">总消息数</div><div class="big">{{ store.stats.total }}</div></div>
          <div class="card">
            <div class="label">时间范围</div>
            <div class="text-[12px] mono leading-5">
              {{ fmtTime(store.stats.tsFirst) }}<br />{{ fmtTime(store.stats.tsLast) }}
            </div>
          </div>
          <div class="card">
            <div class="label">会话 / 设备</div>
            <div class="text-[12px] mono leading-5 break-all">
              {{ store.stats.sessions.length }} 个会话<br />
              <span v-for="d in store.stats.devices" :key="d">{{ d }} </span>
            </div>
          </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <div class="sec-title">消息类型分布</div>
            <div v-for="[t, n] in store.stats.byType" :key="t" class="flex items-center gap-2 h-6">
              <div class="w-40 truncate text-[12px]" :title="t">{{ t }}</div>
              <div class="flex-1 h-3 bg-bg-base rounded overflow-hidden">
                <div
                  class="h-full bg-accent/70 rounded"
                  :style="{ width: `${(n / store.stats.total) * 100}%` }"
                />
              </div>
              <div class="mono text-[12px] text-text-dim w-10 text-right">{{ n }}</div>
            </div>
          </div>
          <div>
            <div class="sec-title">Topic 分布（前 20）</div>
            <div v-for="[t, n] in store.stats.byTopic.slice(0, 20)" :key="t" class="flex items-center gap-2 h-6">
              <div class="w-56 truncate text-[12px]" :title="t">{{ t }}</div>
              <div class="flex-1 h-3 bg-bg-base rounded overflow-hidden">
                <div
                  class="h-full bg-purple/60 rounded"
                  :style="{ width: `${(n / (store.stats.byTopic[0]?.[1] || 1)) * 100}%` }"
                />
              </div>
              <div class="mono text-[12px] text-text-dim w-10 text-right">{{ n }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
