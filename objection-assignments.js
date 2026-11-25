/* Shared by the site and the downloadable, standalone editor. */
function createObjectionAssignments(bank, layouts, published, user) {
  const entries = [];
  const byText = new Map();
  const templates = [];
  const targets = new Map();
  const keyOf = (title, text) => JSON.stringify([title.trim(), text.replace(/\r\n/g, '\n').trim()]);
  const department = user.role === 'HEAD' && user.departmentScripts?.length
    ? new Set(user.departmentScripts.map(String)) : null;
  function register(answer, group = '', source = '') {
    if (!answer || typeof answer.title !== 'string' || typeof answer.text !== 'string' ||
        answer.origin === 'trainer' || answer.trainerBlockId || String(answer.id || '').startsWith('tr_obj_')) return null;
    const key = keyOf(answer.title, answer.text);
    let entry = byText.get(key);
    if (!entry) {
      entry = { id: entries.length, title: answer.title, text: answer.text, groups: [], sources: [] };
      byText.set(key, entry);
      entries.push(entry);
      templates.push(answer);
    }
    if (group && !entry.groups.includes(group)) entry.groups.push(group);
    if (source && !entry.sources.includes(source)) entry.sources.push(source);
    if (answer.textFormat && !templates[entry.id].textFormat) templates[entry.id] = answer;
    return entry.id;
  }
  for (const answer of bank) register(answer, answer.group || 'Общая база');
  for (const layout of layouts) {
    if (!layout?.id || !layout.name || layout.autoSaveOf || /^(Перед изменением|Автосохранение ·)/i.test(layout.name)) continue;
    const data = layout.data;
    if (!Array.isArray(data?.objections)) continue;
    const ids = data.objections.map(answer => register(answer, '', layout.name));
    if (!Array.isArray(data.stages) || (department && !department.has(String(layout.id)))) continue;
    const stages = [];
    data.stages.forEach((stage, index) => {
      if (!stage || stage.hidden || !stage.title || !Array.isArray(stage.objectionIds)) return;
      stages.push({ index, id: stage.id || '', title: stage.title,
        entries: stage.objectionIds.map(i => ids[i]).filter(i => Number.isInteger(i)) });
    });
    targets.set(layout.id, { layout, ids, summary: { id: layout.id, name: layout.name,
      channel: layout.channel || '', variant: layout.variant || '', stages } });
  }
  for (const answer of published?.objections || []) register(answer, '', 'Рабочая версия');
  const catalog = { entries, layouts: Array.from(targets.values(), item => item.summary) };

  // Build replacements first. A stale target or a full layout cancels the whole batch.
  function assign(request) {
    const fail = (message, status = 409) => { throw Object.assign(new Error(message), { status }); };
    if (typeof request?.title !== 'string' || typeof request.text !== 'string' ||
        !Array.isArray(request.targets) || !request.targets.length) fail('Выберите возражение, блок и скрипты.', 400);
    const entry = byText.get(keyOf(request.title, request.text));
    if (!entry) fail('Возражение изменилось. Обновите список и выберите его снова.');
    const changes = new Map();
    const seen = new Set();
    for (const target of request.targets) {
      const item = targets.get(target?.layoutId);
      if (!item) fail('Один из выбранных скриптов больше недоступен.');
      if (seen.has(target.layoutId)) fail('Выберите один блок в каждом скрипте.', 400);
      seen.add(target.layoutId);
      const { layout, ids } = item;
      const stage = item.summary.stages.find(s => s.index === target.index && s.id === target.id && s.title === target.title);
      if (!stage) fail('Блок в скрипте «' + layout.name + '» изменился. Обновите список.');
      if (stage.entries.includes(entry.id)) continue;
      let index = ids.indexOf(entry.id);
      const data = layout.data;
      let objections = data.objections;
      if (index < 0) {
        if (objections.length >= 200) fail('В скрипте «' + layout.name + '» уже 200 возражений.');
        if (entry.title.length > 300 || entry.text.length > 16000) fail('Текст превышает допустимую длину возражения в макете.');
        index = objections.length;
        const source = templates[entry.id];
        objections = [...objections, { title: source.title, text: source.text,
          textFormat: source.textFormat || { style: {}, ranges: [] },
          origin: source.origin === 'document' ? 'document' : 'suggested', nextStageId: '' }];
      }
      const stages = data.stages.slice();
      stages[stage.index] = { ...stages[stage.index], objectionIds: [...stages[stage.index].objectionIds, index] };
      changes.set(layout.id, { ...layout, data: { ...data, objections, stages }, savedAt: Date.now() });
    }
    return { layouts: layouts.map(layout => changes.get(layout?.id) || layout), added: changes.size };
  }
  return { catalog, assign };
}

if (typeof module !== 'undefined' && module.exports) module.exports = createObjectionAssignments;
