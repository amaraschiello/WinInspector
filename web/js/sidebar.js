/**
 * Renders the collapsible 22-category troubleshooting sidebar with instant search.
 */

export function renderSidebar({ container, catalog, selectedId, expandedCategories, searchText, onlyImplemented, onSelect }) {
  container.replaceChildren();

  const query = (searchText || '').trim().toLowerCase();
  const categories = catalog?.categories || [];
  const expandedSet = expandedCategories || new Set();

  let renderedCount = 0;

  for (const cat of categories) {
    const matchingSubs = (cat.subCategories || []).filter((sub) => {
      if (onlyImplemented && !sub.implemented) return false;
      if (!query) return true;
      const haystack = [
        cat.name,
        cat.number,
        sub.name,
        sub.id,
        sub.description,
        ...(sub.keywords || []),
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });

    if (matchingSubs.length === 0) continue;
    renderedCount += matchingSubs.length;

    const isExpanded = Boolean(query) || expandedSet.has(cat.id);

    const group = document.createElement('div');
    group.className = 'cat-group';

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'cat-group-header';

    const titleSpan = document.createElement('span');
    titleSpan.textContent = `${cat.number}. ${cat.name}`;
    const caret = document.createElement('span');
    caret.className = 'muted';
    caret.textContent = isExpanded ? '▾' : '▸';
    header.append(titleSpan, caret);

    const itemsWrap = document.createElement('div');
    itemsWrap.className = isExpanded ? 'cat-items' : 'cat-items hidden';

    header.addEventListener('click', () => {
      const collapsed = itemsWrap.classList.toggle('hidden');
      if (collapsed) {
        expandedSet.delete(cat.id);
      } else {
        expandedSet.add(cat.id);
      }
      caret.textContent = collapsed ? '▸' : '▾';
    });

    for (const sub of matchingSubs) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'cat-item';
      if (sub.id === selectedId) btn.classList.add('active');
      if (!sub.implemented) btn.classList.add('planned');
      btn.title = sub.description || sub.name;

      const labelSpan = document.createElement('span');
      labelSpan.textContent = sub.name;

      const dot = document.createElement('span');
      dot.className = `status-dot ${sub.implemented ? 'ready' : 'planned'}`;
      dot.title = sub.implemented ? 'Ready to run' : 'Planned (Phase 2)';

      btn.append(labelSpan, dot);
      btn.addEventListener('click', () => onSelect(cat, sub));
      itemsWrap.appendChild(btn);
    }

    group.append(header, itemsWrap);
    container.appendChild(group);
  }

  if (renderedCount === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state small';
    empty.textContent = 'No matching troubleshooting categories.';
    container.appendChild(empty);
  }
}
