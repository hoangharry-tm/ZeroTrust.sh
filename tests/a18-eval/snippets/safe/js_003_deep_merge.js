function deepMerge(target, source) {
  const result = Object.assign({}, target);
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor') continue;
    result[key] = source[key];
  }
  return result;
}
