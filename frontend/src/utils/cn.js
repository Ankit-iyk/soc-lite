// src/utils/cn.js
// Tiny utility to join class names (avoids importing a library for something simple)
export function cn(...classes) {
  return classes.filter(Boolean).join(' ');
}
