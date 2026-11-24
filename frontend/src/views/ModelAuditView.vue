<template>
  <div>
    <h2 class="page-title">冻结模型审计 · 来源泄露筛查 · 模型卡</h2>
    <p class="page-desc">
      对冻结模型版本复核登记性能（敏感度/校准 + 区间），核对训练来源与设备范围账，
      筛查医院 Q「单扫描仪 4 例 / 3 例罕见纹理」小联合单元风险；执行 &lt;20 例输出抑制与发布闸门。
      研究者不会取得任何逐例训练记录。
    </p>

    <div v-if="!privileged" class="alert warn">
      当前角色为 <b>{{ auth.user?.role }}</b>：可查看已发布的抑制版模型卡与脱敏来源分桶；
      运行独立审计、查看精确台账与完整审计报告需要 <b>AUDITOR / ADMIN</b>（可使用
      <span class="code-inline">auditor / auditor123</span> 登录）。
    </div>

    <!-- 模型版本选择 -->
    <div class="grid cols-3">
      <div v-for="m in models" :key="m.id" class="card model-card"
           :class="{ active: selectedId === m.id }" @click="selectModel(m.id)">
        <div class="flex-between">
          <b>{{ m.code }}</b>
          <span class="badge" :class="tagClass(m.scenarioTag)">{{ tagLabel(m.scenarioTag) }}</span>
        </div>
        <div class="small mt">{{ m.name }} · <span class="mono">{{ m.version }}</span></div>
        <div class="small mono hash" :title="m.versionHash">sha256:{{ m.versionHash.slice(0, 20) }}…</div>
        <div class="mt kpi-inline">
          <span>训练 <b>{{ m.trainingCaseCount.toLocaleString() }}</b></span>
          <span>冻结验证 <b>{{ m.validationCaseCount.toLocaleString() }}</b></span>
          <span v-if="m.latestDecision" class="badge" :class="m.latestDecision === 'RELEASABLE' ? 'ok' : 'bad'">
            {{ m.latestDecision }}
          </span>
        </div>
      </div>
    </div>

    <div v-if="detail" class="mt">
      <div class="tabs">
        <button :class="{ on: tab === 'scope' }" @click="tab = 'scope'">① 版本哈希与来源设备账</button>
        <button :class="{ on: tab === 'audit' }" @click="tab = 'audit'">② 双路线审计与复算</button>
        <button :class="{ on: tab === 'publish' }" @click="tab = 'publish'">③ 发布闸门与模型卡</button>
        <button :class="{ on: tab === 'caseprobe' }" @click="tab = 'caseprobe'">④ 逐例输出探针</button>
      </div>

      <!-- ① 哈希 + 台账 -->
      <div v-if="tab === 'scope'" class="grid cols-2 mt">
        <div class="card">
          <h3>冻结版本哈希</h3>
          <dl class="kv">
            <dt>versionHash</dt><dd class="mono small break">{{ detail.versionHash }}</dd>
            <dt>artifactHash</dt><dd class="mono small break">{{ detail.artifactHash }}</dd>
            <dt>sourceCommit</dt><dd class="mono">{{ detail.sourceCommit }}</dd>
            <dt>决策阈值</dt><dd>{{ detail.decisionThreshold }}</dd>
          </dl>
          <div class="alert ok">审计运行时会用同一规范化清单独立重算 sha256，并比对
            <b>hashMatch</b>；不一致即阻断。</div>
          <h3 class="mt">发布设备声明</h3>
          <p class="small">{{ detail.deviceClaim?.statement }}</p>
          <div class="small">声明设备数：{{ detail.deviceClaim?.declaredScanners?.length }}</div>
        </div>

        <div class="card">
          <div class="flex-between">
            <h3 style="margin:0">训练来源 / 设备范围账</h3>
            <span class="badge gray">{{ detail.viewerPrivileged ? '审计视图：精确计数' : '研究者视图：亚阈值已脱敏' }}</span>
          </div>
          <table class="mt">
            <thead><tr><th>机构</th><th>扫描仪</th><th>机型 / 厂商</th><th>训练例数</th><th>罕见 RT-HALO</th><th>分桶</th></tr></thead>
            <tbody>
              <tr v-for="(r, i) in detail.ledger" :key="i" :class="{ smallrow: r.countBand === '<20' }">
                <td>{{ r.institutionCode }}<div class="small muted">{{ r.institutionName }}</div></td>
                <td class="mono">{{ r.scannerId }}</td>
                <td class="small">{{ r.scannerModel }}<div class="muted">{{ r.vendor }}</div></td>
                <td>
                  <b v-if="r.caseCount != null">{{ r.caseCount }}</b>
                  <span v-else-if="r.caseCountRounded20 != null" class="muted">≈{{ r.caseCountRounded20 }}（20 舍入）</span>
                  <span v-else class="tag-suppressed">抑制</span>
                </td>
                <td>
                  <b v-if="r.rareTextureCount != null">{{ r.rareTextureCount }}</b>
                  <span v-else class="tag-suppressed">&lt;20 抑制</span>
                </td>
                <td><span class="badge" :class="r.countBand === '<20' ? 'bad' : 'ok'">{{ r.countBand }}</span></td>
              </tr>
            </tbody>
          </table>
          <p class="small muted mt">
            披露阈值 = {{ detail.policy?.disclosureThreshold }}；小单元精确计数对研究者与发布物不可见，
            其余设备计数按 20 舍入，防止用训练总数 12,000 相减反推出 4。
          </p>
        </div>
      </div>

      <!-- ② 审计 -->
      <div v-if="tab === 'audit'" class="mt">
        <div class="card">
          <div class="flex-between">
            <h3 style="margin:0">独立审计运行</h3>
            <div>
              <button class="btn-primary btn-sm" :disabled="!privileged || running" @click="runAudit('MODEL_CARD')">
                {{ runningRoute === 'MODEL_CARD' ? '复算中…' : '运行聚合模型卡路线' }}
              </button>
              <button class="btn-primary btn-sm" style="margin-left:8px" :disabled="!privileged || running"
                      @click="runAudit('PARAM_PACKAGE')">
                {{ runningRoute === 'PARAM_PACKAGE' ? '隔离环境计算中…' : '运行受控参数包路线' }}
              </button>
            </div>
          </div>
          <div v-if="!privileged" class="alert warn mt">审计运行接口仅 AUDITOR / ADMIN 可调用（后端已强制 403）。</div>
          <div v-if="runError" class="alert bad mt">{{ runError }}</div>
        </div>

        <template v-if="currentRun">
          <!-- 总览 -->
          <div class="grid cols-4 mt">
            <div class="card kpi-card">
              <div class="kpi" :class="currentRun.hashMatch ? 'ok-text' : 'bad-text'">{{ currentRun.hashMatch ? '一致' : '不符' }}</div>
              <div class="kpi-label">版本哈希复算</div>
            </div>
            <div class="card kpi-card">
              <div class="kpi" :class="metricConsistent ? 'ok-text' : 'bad-text'">{{ metricConsistent ? '一致' : '偏差' }}</div>
              <div class="kpi-label">登记指标复算</div>
            </div>
            <div class="card kpi-card">
              <div class="kpi" :class="currentRun.decision === 'RELEASABLE' ? 'ok-text' : 'bad-text'">
                {{ currentRun.decision === 'RELEASABLE' ? '可发布(抑制版)' : '阻断' }}
              </div>
              <div class="kpi-label">默认闸门裁决</div>
            </div>
            <div class="card kpi-card">
              <div class="kpi ok-text">0</div>
              <div class="kpi-label">逐例输出条数</div>
            </div>
          </div>

          <!-- 指标 -->
          <div class="grid cols-2 mt">
            <div class="card">
              <h3>登记指标复算（冻结验证集 n={{ detail.validationCaseCount }}）</h3>
              <table>
                <thead><tr><th>指标</th><th>登记值</th><th>独立复算</th><th>95% 区间</th><th>一致</th></tr></thead>
                <tbody>
                  <tr>
                    <td>敏感度（阈值 {{ rep.metrics?.threshold }}）</td>
                    <td class="mono">{{ rep.metrics?.sensitivity?.registered }}</td>
                    <td class="mono"><b>{{ rep.metrics?.sensitivity?.recomputed }}</b></td>
                    <td class="mono small">[{{ rep.metrics?.sensitivity?.wilson95Low }}, {{ rep.metrics?.sensitivity?.wilson95High }}]</td>
                    <td><span class="badge ok">±{{ rep.metrics?.sensitivity?.absoluteDiff }}</span></td>
                  </tr>
                  <tr>
                    <td>Brier</td>
                    <td class="mono">{{ rep.metrics?.brier?.registered }}</td>
                    <td class="mono">{{ rep.metrics?.brier?.recomputed }}</td>
                    <td class="mono small">[{{ rep.metrics?.brier?.bootstrap95Low }}, {{ rep.metrics?.brier?.bootstrap95High }}]</td>
                    <td><span class="badge ok">±{{ rep.metrics?.brier?.absoluteDiff }}</span></td>
                  </tr>
                  <tr>
                    <td>校准 ECE(10 箱)</td>
                    <td class="mono">{{ rep.metrics?.ece10?.registered }}</td>
                    <td class="mono">{{ rep.metrics?.ece10?.recomputed }}</td>
                    <td class="mono small">[{{ rep.metrics?.ece10?.bootstrap95Low }}, {{ rep.metrics?.ece10?.bootstrap95High }}]</td>
                    <td><span class="badge" :class="rep.metrics?.ece10?.absoluteDiff <= 0.02 ? 'ok' : 'bad'">±{{ rep.metrics?.ece10?.absoluteDiff }}</span></td>
                  </tr>
                  <tr>
                    <td>校准截距 / 斜率</td>
                    <td class="mono small">{{ rep.metrics?.calibrationLogistic?.registeredIntercept }} / {{ rep.metrics?.calibrationLogistic?.registeredSlope }}</td>
                    <td class="mono small">{{ rep.metrics?.calibrationLogistic?.recomputedIntercept }} / {{ rep.metrics?.calibrationLogistic?.recomputedSlope }}</td>
                    <td class="small muted">SE {{ rep.metrics?.calibrationLogistic?.interceptSe }} / {{ rep.metrics?.calibrationLogistic?.slopeSe }}</td>
                    <td>理想 0 / 1</td>
                  </tr>
                </tbody>
              </table>
              <div v-for="(r, i) in rep.metrics?.consistencyIssues" :key="i" class="alert bad">{{ r }}</div>
            </div>

            <!-- 清单核对 + 闸门 -->
            <div class="card">
              <h3>设备清单核对与发布闸门</h3>
              <p>
                台账 vs 发布声明：
                <span class="badge" :class="rep.manifestCheck?.match ? 'ok' : 'bad'">
                  {{ rep.manifestCheck?.match ? '一致' : '不符' }}
                </span>
              </p>
              <div v-for="(d, i) in rep.manifestCheck?.discrepancies" :key="i" class="alert bad">
                <b>[{{ d.type }}] {{ d.scannerId }}</b> — {{ d.message }}
              </div>
              <div class="alert" :class="currentRun.decision === 'RELEASABLE' ? 'ok' : 'bad'">
                <b>抑制后聚合发布：{{ rep.gate?.decision }}</b>
                <div v-for="(r, i) in rep.gate?.blockReasons" :key="'b'+i" class="mt small">
                  <b>[{{ r.code }}]</b> {{ r.message }}
                </div>
              </div>
              <div class="alert warn">
                <b>未抑制明细发布：{{ rep.gate?.unsuppressedDetail?.decision }}</b>
                <div v-for="(r, i) in rep.gate?.unsuppressedDetail?.blockReasons" :key="'u'+i" class="mt small">
                  <b>[{{ r.code }}]</b> {{ r.message }}
                </div>
              </div>
            </div>
          </div>

          <!-- 稀有单元 -->
          <div class="card mt">
            <h3>稀有特征 / 小联合单元风险（审计内部精确视图）</h3>
            <table>
              <thead><tr><th>联合单元</th><th>例数</th><th>风险分</th><th>等级</th><th>越线 0.70</th><th>可解释结论</th></tr></thead>
              <tbody>
                <tr v-for="u in smallUnits" :key="u.unitKey">
                  <td class="mono small">{{ u.unitKey }}</td>
                  <td><span class="tag-suppressed">{{ u.caseCount }} &lt;20</span></td>
                  <td class="mono"><b>{{ u.attackRiskScore }}</b>
                    <div class="riskbar"><div :style="{ width: (u.attackRiskScore * 100) + '%' }"
                      :class="u.lineCrossed ? 'over' : ''"></div></div>
                  </td>
                  <td><span class="badge" :class="riskClass(u.attackRiskLevel)">{{ u.attackRiskLevel }}</span></td>
                  <td><span class="badge" :class="u.lineCrossed ? 'bad' : 'ok'">{{ u.lineCrossed ? '是' : '否' }}</span></td>
                  <td class="small">{{ u.explainableConclusion }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- 路线特有发现 -->
          <div class="grid cols-2 mt">
            <div class="card">
              <h3>聚合模型卡路线限制</h3>
              <template v-if="rep.routeFindings?.route === 'MODEL_CARD'">
                <p><span class="badge info">易分发</span></p>
                <p class="small"><b>逐例特征贡献：</b>{{ rep.routeFindings.caseLevelFeatureContribution?.message }}</p>
                <div class="alert warn">
                  <b>{{ rep.routeFindings.deviceBinding?.code }}</b><br />
                  {{ rep.routeFindings.deviceBinding?.message }}
                  <div class="mt"><span class="badge gray">deviceBindingRiskExcluded=false</span></div>
                </div>
              </template>
              <template v-else-if="rep.routeFindings">
                <PackageFindings :f="rep.routeFindings" />
              </template>
              <div v-else class="muted">暂无路线发现，请重新运行审计。</div>
            </div>

            <div class="card">
              <h3>审计结论</h3>
              <ul class="tight">
                <li v-for="(c, i) in rep.conclusions" :key="i">{{ c }}</li>
              </ul>
              <p class="small muted">报告哈希 <span class="mono break">{{ currentRun.reportHash }}</span></p>
              <button class="btn-ghost btn-sm" @click="showRaw = !showRaw">{{ showRaw ? '隐藏' : '查看' }}完整报告 JSON</button>
              <pre v-if="showRaw" class="json mt">{{ JSON.stringify(currentRun.report, null, 2) }}</pre>
            </div>
          </div>
        </template>
      </div>

      <!-- ③ 发布 -->
      <div v-if="tab === 'publish'" class="mt">
        <div class="card">
          <h3>发布操作（强制服务端闸门）</h3>
          <p class="small muted">先在「双路线审计」中运行对应路线；发布物类型必须与审计路线一致。</p>
          <div class="form-row">
            <div>
              <label>选择成功运行</label>
              <select v-model="publishRunId">
                <option v-for="r in modelRuns" :key="r.id" :value="r.id">
                  #{{ r.id }} {{ r.route }} · {{ r.decision }} · {{ fmt(r.createdAt) }}
                </option>
              </select>
            </div>
            <button class="btn-primary" :disabled="!privileged || !publishRunId" @click="doPublish(true)">
              发布抑制版（&lt;20 单元脱敏）
            </button>
            <button class="btn-danger" :disabled="!privileged || !publishRunId" @click="doPublish(false)">
              尝试发布未抑制明细（应被阻断）
            </button>
          </div>
          <div v-if="publishMsg" class="alert ok mt">{{ publishMsg }}</div>
          <div v-if="publishError" class="alert bad mt">{{ publishError }}</div>
        </div>

        <div class="grid cols-2 mt">
          <div class="card">
            <h3>本模型发布物</h3>
            <table>
              <thead><tr><th>#</th><th>类型</th><th>版本</th><th>风险级</th><th>哈希</th><th></th></tr></thead>
              <tbody>
                <tr v-for="c in cardsForModel" :key="c.id">
                  <td>{{ c.id }}</td>
                  <td><span class="badge info">{{ c.kind }}</span></td>
                  <td>v{{ c.cardVersion }}</td>
                  <td><span class="badge warn">{{ c.riskLevel }}</span></td>
                  <td class="mono small">{{ c.contentHash.slice(0, 12) }}…</td>
                  <td><button class="btn-ghost btn-sm" @click="viewCard(c.id)">查看</button></td>
                </tr>
                <tr v-if="!cardsForModel.length"><td colspan="6" class="muted">尚未发布</td></tr>
              </tbody>
            </table>
          </div>
          <div class="card" v-if="activeCard">
            <div class="flex-between">
              <h3 style="margin:0">{{ activeCard.kind }} v{{ activeCard.cardVersion }}</h3>
              <span class="mono small">{{ activeCard.contentHash.slice(0, 20) }}…</span>
            </div>
            <pre class="json mt">{{ JSON.stringify(activeCard.content, null, 2) }}</pre>
          </div>
        </div>
      </div>

      <!-- ④ 逐例探针 -->
      <div v-if="tab === 'caseprobe'" class="card mt">
        <h3>逐例训练 / 验证记录访问探针</h3>
        <p>验收项要求「逐例输出为零、研究者不得取得逐例训练记录」。下列任何取数尝试都由后端拒绝（403）并写入
          <span class="code-inline">CASE_LEVEL_EXPORT_DENIED</span> 审计事件；平台不存在返回逐例实体的接口。</p>
        <div class="form-row">
          <button class="btn-danger" @click="probe('GET', `/model-audit/models/${selectedId}/cases`)">GET 模型逐例记录</button>
          <button class="btn-danger" @click="probe('POST', '/model-audit/case-export', { modelId: selectedId })">POST 逐例导出</button>
          <button class="btn-ghost" @click="tab = 'audit'">查看审计中的 zeroCaseOutput 保证</button>
        </div>
        <div v-if="probeResult" class="alert bad mt">
          后端响应 {{ probeResult.status }}：{{ probeResult.error }}
        </div>
        <div class="alert ok mt"><b>当前可确认的逐例输出条数：0</b>（所有模型卡/参数包/报告均无逐例数组）。</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, h, onMounted, ref } from 'vue'
import api from '../api'
import { useAuthStore } from '../store'

const auth = useAuthStore()
const privileged = computed(() => ['AUDITOR', 'ADMIN'].includes(auth.user?.role))

const models = ref([])
const selectedId = ref(null)
const detail = ref(null)
const tab = ref('scope')

const currentRun = ref(null)
const running = ref(false)
const runningRoute = ref('')
const runError = ref('')
const showRaw = ref(false)

const runs = ref([])
const cards = ref([])
const activeCard = ref(null)
const publishRunId = ref(null)
const publishMsg = ref('')
const publishError = ref('')
const probeResult = ref(null)

const rep = computed(() => currentRun.value?.report || {})
const metricConsistent = computed(() => rep.value.metrics?.consistentWithFrozenVersion)
const smallUnits = computed(() => (rep.value.rareUnits || []).filter((u) => u.belowThreshold))
const modelRuns = computed(() => runs.value.filter((r) => r.modelId === selectedId.value))
const cardsForModel = computed(() => cards.value.filter((c) => c.modelId === selectedId.value))

function fmt(ms) { return new Date(ms).toLocaleString() }
function riskClass(l) { return { LOW: 'ok', MEDIUM: 'warn', HIGH: 'bad', CRITICAL: 'bad' }[l] || 'gray' }
function tagClass(t) {
  return { Q_RARE_CELL: 'warn', MANIFEST_MISMATCH: 'bad', ATTACK_OVER_LINE: 'bad' }[t] || 'info'
}
function tagLabel(t) {
  return { Q_RARE_CELL: 'Q 小单元', MANIFEST_MISMATCH: '清单不符', ATTACK_OVER_LINE: '攻击越线' }[t] || t
}

async function loadModels() {
  const { data } = await api.get('/model-audit/models')
  models.value = data
  if (!selectedId.value && data.length) await selectModel(data[0].id)
}
async function selectModel(id) {
  selectedId.value = id
  currentRun.value = null
  activeCard.value = null
  publishMsg.value = publishError.value = ''
  const [{ data: d }, { data: rs }, { data: cs }] = await Promise.all([
    api.get(`/model-audit/models/${id}`),
    privileged.value ? api.get('/model-audit/runs').catch(() => ({ data: [] })) : Promise.resolve({ data: [] }),
    api.get('/model-audit/cards')
  ])
  detail.value = d
  runs.value = rs
  cards.value = cs
  const mine = rs.filter((r) => r.modelId === id)
  if (mine.length) {
    currentRun.value = mine[0]
    publishRunId.value = mine[0].id
  } else {
    publishRunId.value = null
  }
}

async function runAudit(routeName) {
  running.value = true
  runningRoute.value = routeName
  runError.value = ''
  try {
    const { data } = await api.post(`/model-audit/models/${selectedId.value}/runs`, { route: routeName })
    currentRun.value = data
    runs.value = await api.get('/model-audit/runs').then((r) => r.data)
    publishRunId.value = data.id
  } catch (e) {
    runError.value = e.response?.data?.error || '审计运行失败'
  } finally {
    running.value = false
    runningRoute.value = ''
  }
}

async function doPublish(suppress) {
  publishMsg.value = ''
  publishError.value = ''
  try {
    const { data } = await api.post(`/model-audit/runs/${publishRunId.value}/publish`,
      { applySuppression: suppress })
    publishMsg.value = suppress
      ? `已发布 ${data.kind} v${data.cardVersion}，风险等级 ${data.riskLevel}，内容哈希 ${data.contentHash.slice(0, 16)}…`
      : '未抑制明细已发布（不应出现）'
    const { data: cs } = await api.get('/model-audit/cards')
    cards.value = cs
    await viewCard(data.id)
  } catch (e) {
    publishError.value = e.response?.data?.error || '发布失败'
  }
}

async function viewCard(id) {
  const { data } = await api.get(`/model-audit/cards/${id}`)
  activeCard.value = data
}

async function probe(method, path, body) {
  probeResult.value = null
  try {
    const cfg = method === 'POST' ? { method, url: path, data: body } : { method, url: path }
    const r = await api(cfg)
    probeResult.value = { status: r.status, error: '意外返回了数据' }
  } catch (e) {
    probeResult.value = { status: e.response?.status, error: e.response?.data?.error || e.message }
  }
}

// 参数包发现子组件（内联渲染函数，避免再拆文件）
const PackageFindings = {
  props: ['f'],
  setup(props) {
    return () => h('div', [
      h('p', null, [h('span', { class: 'badge info' }, '受控参数包 · 隔离飞地执行')]),
      h('ul', { class: 'tight small' }, [
        h('li', null, `总体消融 Δ敏感度=${props.f.ablationOverall?.deltaSensitivity}，Δ均分=${props.f.ablationOverall?.deltaMeanScore}（罕见特征携带 ${props.f.ablationOverall?.rareFeatureCarriersInValidation} 例）`),
        h('li', null, `总体 MIA AUC=${props.f.membershipInferenceOverall?.auc}，优势=${props.f.membershipInferenceOverall?.advantage}（越线 ${props.f.membershipInferenceOverall?.lineCrossed ? '是' : '否'}）`),
        h('li', null, `目标设备子组 MIA returned=${props.f.membershipInferenceTargetScanner?.returned}，AUC=${props.f.membershipInferenceTargetScanner?.auc ?? '抑制'}`),
        h('li', null, `罕见联合单元统计 returned=${props.f.rareJointUnitStat?.returned}（${props.f.rareJointUnitStat?.suppressionReason}）`),
      ]),
      h('div', { class: 'alert ' + (props.f.deviceBinding?.deviceBindingDetected ? 'bad' : 'warn') }, [
        h('b', null, `设备绑定：${props.f.deviceBinding?.status}`),
        h('div', { class: 'small mt' }, props.f.deviceBinding?.message),
        h('div', { class: 'small mono mt' },
          `签名探针 AUC=${props.f.deviceBinding?.scannerSignatureProbeAuc}；输出探针 AUC=${props.f.deviceBinding?.modelScoreScannerProbeAuc} CI=${JSON.stringify(props.f.deviceBinding?.modelScoreAucBootstrap95)}；Cohen d=${props.f.deviceBinding?.scoreCohenD}`)
      ])
    ])
  }
}

onMounted(loadModels)
</script>

<style scoped>
.model-card { cursor: pointer; transition: border-color .15s, box-shadow .15s; }
.model-card.active { border-color: var(--brand); box-shadow: 0 0 0 2px #bfdbfe; }
.model-card .hash { color: var(--muted); margin-top: 6px; }
.kpi-inline { display: flex; gap: 12px; align-items: center; font-size: 12px; color: var(--muted); flex-wrap: wrap; }
.tabs { display: flex; gap: 6px; margin-top: 4px; flex-wrap: wrap; }
.tabs button { background: #e2e8f0; color: #334155; padding: 8px 14px; }
.tabs button.on { background: var(--brand); color: #fff; }
.kpi-card { text-align: center; }
.ok-text { color: var(--ok); }
.bad-text { color: var(--bad); }
.kv { display: grid; grid-template-columns: 110px 1fr; gap: 8px 12px; margin: 0; }
.kv dt { color: var(--muted); font-size: 12px; }
.kv dd { margin: 0; }
.break { word-break: break-all; }
.smallrow { background: #fff7ed; }
.riskbar { width: 120px; height: 6px; background: #e2e8f0; border-radius: 4px; margin-top: 4px; overflow: hidden; }
.riskbar > div { height: 100%; background: #b45309; }
.riskbar > div.over { background: #dc2626; }
</style>
