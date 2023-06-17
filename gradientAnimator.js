export const gradientAnimator = (element, opts) => {
  let startColor = `linear-gradient(${opts.angle.start}deg,`
  opts.colors.forEach(color => {
    startColor += ` rgb(${color.start.r}, ${color.start.g}, ${color.start.b}),`
  })
  startColor = startColor.substring(0, startColor.length - 2)
  element.style.background = startColor

  let timer = 0
  setInterval(() => {
    timer += 0.1
    const p = Math.pow(Math.sin(timer * Math.PI / opts.duration), 2)
    let newColor = `linear-gradient(${lerp(opts.angle.start, opts.angle.end, p)}deg,`
    opts.colors.forEach(color => {
      newColor += ` rgb(${lerp(color.start.r, color.end.r, p)}, ${lerp(color.start.g, color.end.g, p)}, ${lerp(color.start.b, color.end.b, p)}),`
    })
    newColor = newColor.substring(0, newColor.length - 2)
    element.style.background = newColor
  }, 100)
}

const lerp = (a, b, alpha) => {
  return a + alpha * (b - a)
}
