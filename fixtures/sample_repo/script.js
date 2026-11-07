function render(html, code) {
  document.getElementById("x").innerHTML = html;
  return eval(code);
}
