<script>
  const AUDIT_PAGE_SIZE = 25

  let me = $state(null)
  let mappings = $state([])
  let loading = $state(true)
  let error = $state('')
  let roleId = $state('')
  let groupName = $state('')
  let saving = $state(false)
  let revokeUser = $state('')
  let revoking = $state(false)
  let notice = $state('')

  let auditItems = $state([])
  let auditTotal = $state(0)
  let auditOffset = $state(0)
  let auditLoading = $state(false)
  let auditError = $state('')

  async function load() {
    loading = true
    error = ''
    try {
      const meRes = await fetch('/api/me', { credentials: 'same-origin' })
      if (meRes.status === 401) {
        me = null
        loading = false
        return
      }
      if (!meRes.ok) {
        throw new Error('Failed to load session')
      }
      me = await meRes.json()
      if (!me.admin) {
        loading = false
        return
      }
      const mapRes = await fetch('/api/mappings', { credentials: 'same-origin' })
      if (!mapRes.ok) {
        throw new Error('Failed to load mappings')
      }
      mappings = await mapRes.json()
      await loadAudit(auditOffset)
    } catch (e) {
      error = e.message || 'Unexpected error'
    } finally {
      loading = false
    }
  }

  async function loadAudit(offset = 0) {
    auditLoading = true
    auditError = ''
    try {
      const qs = new URLSearchParams({
        limit: String(AUDIT_PAGE_SIZE),
        offset: String(Math.max(0, offset)),
      })
      const res = await fetch(`/api/audit?${qs}`, { credentials: 'same-origin' })
      if (!res.ok) {
        throw new Error('Failed to load audit history')
      }
      const page = await res.json()
      auditItems = page.items || []
      auditTotal = page.total || 0
      auditOffset = page.offset || 0
    } catch (e) {
      auditError = e.message || 'Failed to load audit history'
    } finally {
      auditLoading = false
    }
  }

  async function addMapping(e) {
    e.preventDefault()
    saving = true
    error = ''
    notice = ''
    try {
      const res = await fetch('/api/mappings', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role_id: roleId.trim(), group_name: groupName.trim() }),
      })
      if (!res.ok) {
        throw new Error(await res.text())
      }
      roleId = ''
      groupName = ''
      await load()
    } catch (e) {
      error = e.message || 'Failed to save'
    } finally {
      saving = false
    }
  }

  async function removeMapping(m) {
    if (!confirm(`Delete ${m.group_name} ← ${m.role_id}?`)) return
    error = ''
    notice = ''
    try {
      const qs = new URLSearchParams({
        role_id: m.role_id,
        group_name: m.group_name,
      })
      const res = await fetch(`/api/mappings?${qs}`, {
        method: 'DELETE',
        credentials: 'same-origin',
      })
      if (!res.ok) {
        throw new Error(await res.text())
      }
      await load()
    } catch (e) {
      error = e.message || 'Failed to delete'
    }
  }

  async function revokeSessions(e) {
    e.preventDefault()
    const target = revokeUser.trim()
    if (!target) return
    if (!confirm(`Revoke all sessions for Discord user ${target}?`)) return
    revoking = true
    error = ''
    notice = ''
    try {
      const res = await fetch('/api/sessions/revoke', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ discord_user: target }),
      })
      if (!res.ok) {
        throw new Error(await res.text())
      }
      notice = `Revoked sessions for ${target}`
      revokeUser = ''
      await loadAudit(0)
    } catch (e) {
      error = e.message || 'Failed to revoke'
    } finally {
      revoking = false
    }
  }

  function signIn() {
    window.location.href = '/?rd=/admin/'
  }

  async function signOut() {
    await fetch('/_oauth/logout', { credentials: 'same-origin' })
    window.location.href = '/admin/'
  }

  function formatAction(action) {
    switch (action) {
      case 'mapping.upsert':
        return 'Mapping upsert'
      case 'mapping.delete':
        return 'Mapping delete'
      case 'session.revoke_user':
        return 'Revoke sessions'
      default:
        return action
    }
  }

  function formatDetails(details) {
    if (!details || typeof details !== 'object') return '—'
    if (details.group_name && details.role_id) {
      return `${details.group_name} ← ${details.role_id}`
    }
    if (details.discord_user) {
      return details.discord_user
    }
    const keys = Object.keys(details)
    if (keys.length === 0) return '—'
    return JSON.stringify(details)
  }

  function auditRangeLabel() {
    if (auditTotal === 0) return '0 events'
    const start = auditOffset + 1
    const end = Math.min(auditOffset + auditItems.length, auditTotal)
    return `${start}–${end} of ${auditTotal}`
  }

  function canPrevAudit() {
    return auditOffset > 0
  }

  function canNextAudit() {
    return auditOffset + AUDIT_PAGE_SIZE < auditTotal
  }

  $effect(() => {
    load()
  })
</script>

<main class="shell">
  {#if loading}
    <div class="center muted">Loading…</div>
  {:else if !me}
    <div class="center panel">
      <h1>Discord Forward Auth</h1>
      <p class="muted">Sign in with Discord to manage role → group mappings.</p>
      <button type="button" onclick={signIn}>Sign in with Discord</button>
    </div>
  {:else if !me.admin}
    <div class="center panel">
      <h1>Forbidden</h1>
      <p class="muted">
        Signed in as <span class="mono">{me.discord_user}</span>, but you are not in the
        <span class="mono">{me.admin_group}</span> group.
      </p>
      <button type="button" class="secondary" onclick={signOut}>Sign out</button>
    </div>
  {:else}
    <div class="header">
      <div>
        <h1>Role → group mappings</h1>
        <p class="muted">
          Guild <span class="mono">{me.guild_id}</span>
          · admin <span class="mono">{me.discord_user}</span>
        </p>
      </div>
      <button type="button" class="secondary" onclick={signOut}>Sign out</button>
    </div>

    <div class="panel">
      <form class="form-row" onsubmit={addMapping}>
        <input
          bind:value={roleId}
          placeholder="Discord role ID"
          required
          class="mono"
          autocomplete="off"
        />
        <input
          bind:value={groupName}
          placeholder="Group name (e.g. operator)"
          required
          autocomplete="off"
        />
        <button type="submit" disabled={saving}>{saving ? 'Saving…' : 'Add'}</button>
      </form>

      {#if error}
        <p class="error">{error}</p>
      {/if}
      {#if notice}
        <p class="notice">{notice}</p>
      {/if}

      {#if mappings.length === 0}
        <p class="empty">No mappings yet. Bootstrap admins use BOOTSTRAP_ADMIN_ROLE_ID until you add rows here.</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>Group</th>
              <th>Role ID</th>
              <th>Updated</th>
              <th>By</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each mappings as m (m.guild_id + m.role_id + m.group_name)}
              <tr>
                <td>{m.group_name}</td>
                <td class="mono">{m.role_id}</td>
                <td class="muted">{m.updated_at ? new Date(m.updated_at).toLocaleString() : '—'}</td>
                <td class="mono muted">{m.updated_by || '—'}</td>
                <td>
                  <button type="button" class="danger" onclick={() => removeMapping(m)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>

    <div class="panel" style="margin-top: 1.25rem">
      <h2 class="section-title">Revoke sessions</h2>
      <p class="muted" style="margin-top: 0">
        Immediately invalidate all sessions for a Discord user (kick / compromise response).
      </p>
      <form class="form-row" onsubmit={revokeSessions}>
        <input
          bind:value={revokeUser}
          placeholder="Discord user snowflake"
          required
          class="mono"
          autocomplete="off"
        />
        <button type="submit" class="danger" disabled={revoking}>
          {revoking ? 'Revoking…' : 'Revoke sessions'}
        </button>
      </form>
    </div>

    <div class="panel" style="margin-top: 1.25rem">
      <div class="section-header">
        <div>
          <h2 class="section-title">Audit history</h2>
          <p class="muted" style="margin: 0">
            Mapping changes and session revokes. Newest first.
          </p>
        </div>
        <span class="muted">{auditRangeLabel()}</span>
      </div>

      {#if auditError}
        <p class="error">{auditError}</p>
      {/if}

      {#if auditLoading && auditItems.length === 0}
        <p class="empty">Loading audit history…</p>
      {:else if auditItems.length === 0}
        <p class="empty">No audit events yet.</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {#each auditItems as e (e.id)}
              <tr class:dim={auditLoading}>
                <td class="muted">{e.at ? new Date(e.at).toLocaleString() : '—'}</td>
                <td>{formatAction(e.action)}</td>
                <td class="mono muted">{e.actor || '—'}</td>
                <td class="mono muted">{formatDetails(e.details)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      <div class="pager">
        <button
          type="button"
          class="secondary"
          disabled={!canPrevAudit() || auditLoading}
          onclick={() => loadAudit(Math.max(0, auditOffset - AUDIT_PAGE_SIZE))}
        >
          Previous
        </button>
        <button
          type="button"
          class="secondary"
          disabled={!canNextAudit() || auditLoading}
          onclick={() => loadAudit(auditOffset + AUDIT_PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  {/if}
</main>
