class LabLineChart {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.options = options;
    this.series = [];
    this.compareSeries = [];
    this.resizeObserver = new ResizeObserver(() => this.draw());
    this.resizeObserver.observe(canvas);
  }

  setData(series, compareSeries = []) {
    this.series = series || [];
    this.compareSeries = compareSeries || [];
    this.draw();
  }

  draw() {
    const rect = this.canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;
    const width = Math.max(10, Math.floor(rect.width * ratio));
    const height = Math.max(10, Math.floor(rect.height * ratio));
    if (this.canvas.width !== width || this.canvas.height !== height) {
      this.canvas.width = width;
      this.canvas.height = height;
    }

    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;
    ctx.clearRect(0, 0, w, h);

    const pad = { top: 22 * ratio, right: 18 * ratio, bottom: 28 * ratio, left: 40 * ratio };
    const plotW = Math.max(1, w - pad.left - pad.right);
    const plotH = Math.max(1, h - pad.top - pad.bottom);

    const allSeries = [...this.series, ...this.compareSeries];
    const maxLength = allSeries.reduce((acc, item) => Math.max(acc, item.values.length), 0);
    let maxY = 1;
    allSeries.forEach((item) => {
      item.values.forEach((value) => {
        maxY = Math.max(maxY, Number(value) || 0);
      });
    });

    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, w, h);

    ctx.strokeStyle = "rgba(16, 32, 51, 0.12)";
    ctx.lineWidth = 1 * ratio;
    for (let i = 0; i <= 4; i += 1) {
      const y = pad.top + (plotH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(w - pad.right, y);
      ctx.stroke();
    }

    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top);
    ctx.lineTo(pad.left, h - pad.bottom);
    ctx.lineTo(w - pad.right, h - pad.bottom);
    ctx.stroke();

    ctx.font = `${11 * ratio}px "Space Grotesk", "Segoe UI", sans-serif`;
    ctx.fillStyle = "#5a6d82";
    ctx.textBaseline = "middle";
    for (let i = 0; i <= 4; i += 1) {
      const value = ((maxY / 4) * (4 - i)).toFixed(0);
      const y = pad.top + (plotH / 4) * i;
      ctx.fillText(value, 6 * ratio, y);
    }

    const drawLine = (item, dashed) => {
      if (item.values.length < 2) {
        return;
      }
      ctx.beginPath();
      ctx.strokeStyle = item.color;
      ctx.lineWidth = (dashed ? 1.5 : 2.3) * ratio;
      ctx.setLineDash(dashed ? [6 * ratio, 4 * ratio] : []);
      item.values.forEach((value, index) => {
        const x = pad.left + (index / Math.max(1, maxLength - 1)) * plotW;
        const y = pad.top + plotH - ((Number(value) || 0) / maxY) * plotH;
        if (index === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }
      });
      ctx.stroke();
      ctx.setLineDash([]);
    };

    this.series.forEach((item) => drawLine(item, false));
    this.compareSeries.forEach((item) => drawLine(item, true));

    let legendX = pad.left;
    let legendY = 10 * ratio;
    [...this.series, ...this.compareSeries].forEach((item, index) => {
      if (legendX > w - 180 * ratio) {
        legendX = pad.left;
        legendY += 16 * ratio;
      }
      ctx.fillStyle = item.color;
      ctx.fillRect(legendX, legendY, 10 * ratio, 10 * ratio);
      if (index >= this.series.length) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2 * ratio;
        ctx.beginPath();
        ctx.moveTo(legendX, legendY + 5 * ratio);
        ctx.lineTo(legendX + 10 * ratio, legendY + 5 * ratio);
        ctx.stroke();
      }
      ctx.fillStyle = "#33475b";
      ctx.fillText(item.label, legendX + 16 * ratio, legendY + 5 * ratio);
      legendX += (item.label.length + 10) * 7 * ratio;
    });
  }
}

window.LabLineChart = LabLineChart;
