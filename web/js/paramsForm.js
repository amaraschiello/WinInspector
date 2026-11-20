/**
 * Builds dynamic parameter inputs from manifest.json for the selected category.
 */

export function renderParametersForm({ formEl, gridEl, presetsEl, subCategory }) {
  gridEl.replaceChildren();
  presetsEl.replaceChildren();

  if (!subCategory || !subCategory.implemented) {
    formEl.classList.add('hidden');
    return;
  }

  formEl.classList.remove('hidden');
  const params = subCategory.parameters || [];

  let hoursBackInput = null;

  for (const p of params) {
    const group = document.createElement('div');
    group.className = 'field-group';

    const label = document.createElement('label');
    label.textContent = p.label || p.name;
    const inputId = `param_${p.name}`;
    label.setAttribute('for', inputId);
    group.appendChild(label);

    if (p.type === 'select') {
      const select = document.createElement('select');
      select.id = inputId;
      select.dataset.paramName = p.name;
      select.dataset.paramType = 'select';
      for (const optVal of p.options || []) {
        const opt = document.createElement('option');
        opt.value = optVal;
        opt.textContent = optVal;
        if (String(optVal) === String(p.default)) opt.selected = true;
        select.appendChild(opt);
      }
      group.appendChild(select);
    } else if (p.type === 'multiselect') {
      const wrap = document.createElement('div');
      wrap.className = 'multiselect-group';
      wrap.dataset.paramName = p.name;
      wrap.dataset.paramType = 'multiselect';
      const defaults = new Set((p.default || []).map(String));

      for (const optVal of p.options || []) {
        const chip = document.createElement('label');
        chip.className = 'multiselect-chip';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = optVal;
        cb.checked = defaults.has(String(optVal));
        const txt = document.createElement('span');
        txt.textContent = optVal;
        chip.append(cb, txt);
        wrap.appendChild(chip);
      }
      group.appendChild(wrap);
    } else if (p.type === 'number') {
      const input = document.createElement('input');
      input.id = inputId;
      input.type = 'number';
      input.dataset.paramName = p.name;
      input.dataset.paramType = 'number';
      if (p.default !== undefined) input.value = String(p.default);
      if (p.min !== undefined) input.min = String(p.min);
      if (p.max !== undefined) input.max = String(p.max);
      input.style.width = '115px';
      group.appendChild(input);

      if (p.name === 'HoursBack') {
        hoursBackInput = input;
      }
    } else {
      const input = document.createElement('input');
      input.id = inputId;
      input.type = 'text';
      input.dataset.paramName = p.name;
      input.dataset.paramType = 'string';
      if (p.placeholder) input.placeholder = p.placeholder;
      if (p.default !== undefined) input.value = String(p.default);
      group.appendChild(input);
    }

    gridEl.appendChild(group);
  }

  // Quick Lookback Presets whenever HoursBack is present
  if (hoursBackInput) {
    const lbl = document.createElement('span');
    lbl.className = 'muted small';
    lbl.textContent = 'Quick window:';
    presetsEl.appendChild(lbl);

    const presets = [
      { label: '1h', hours: 1 },
      { label: '6h', hours: 6 },
      { label: '24h', hours: 24 },
      { label: '72h', hours: 72 },
      { label: '7d', hours: 168 },
      { label: '30d', hours: 720 },
    ];
    const maxHours = Number(hoursBackInput.max || 2160);
    for (const pr of presets) {
      if (pr.hours > maxHours) continue;
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'preset-btn';
      b.textContent = pr.label;
      b.addEventListener('click', () => {
        hoursBackInput.value = String(pr.hours);
      });
      presetsEl.appendChild(b);
    }
  }
}

export function collectParameterValues(gridEl) {
  const result = {};
  const elements = gridEl.querySelectorAll('[data-param-name]');

  for (const el of elements) {
    const name = el.dataset.paramName;
    const type = el.dataset.paramType;

    if (type === 'multiselect') {
      const checked = Array.from(el.querySelectorAll('input[type="checkbox"]:checked')).map((c) => c.value);
      result[name] = checked;
    } else if (type === 'number') {
      if (el.value !== '') result[name] = Number(el.value);
    } else {
      if (el.value.trim() !== '') result[name] = el.value.trim();
    }
  }

  return result;
}
