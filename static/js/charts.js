/* ===========================================================================
   Linux Guardian -- static/js/charts.js

   REAL CHARTS, DRAWN BY HAND, WITH NO CHARTING LIBRARY.

   WHY NOT Chart.js -- the obvious question, and the answer is the project's
   oldest rule. Chart.js is normally loaded from a CDN, and this machine must
   demonstrate with no internet at all: the graphs would be blank squares in
   the viva. The Debian package (libjs-chart.js) would need apt, which needs
   the network we do not have. Vendoring 200 KB of minified third-party code
   into the repository would mean shipping something nobody in this project can
   explain line by line, which is the one thing CLAUDE.md forbids outright.

   An SVG line chart is a path with some numbers in it. Everything below is
   arithmetic that fits on a page, and every element it produces is inspectable
   in the browser's element panel. That is worth more here than the features of
   a library that would go unused.

   WHAT IT DRAWS
     line(el, points, options)    a time series with axes, a baseline band and
                                  an optional hover readout
     spark(el, points)            a tiny inline trend, no axes

   THE COLOURS COME FROM CSS, NOT FROM HERE. Every element is given a class and
   guardian.css decides what it looks like, so the colour discipline is enforced
   in one file rather than being re-decided in JavaScript.
   =========================================================================== */

(function (global) {
  "use strict";

  const SVG_NS = "http://www.w3.org/2000/svg";

  function make(name, attributes) {
    const node = document.createElementNS(SVG_NS, name);
    for (const key in attributes) {
      node.setAttribute(key, attributes[key]);
    }
    return node;
  }

  /* Round to a sensible number of decimals for display. A CPU percentage wants
     one decimal; a byte rate of 8,432,110 wants none. The rule is "about four
     significant figures", which reads well at every magnitude this project
     produces. */
  function pretty(value) {
    if (value === null || value === undefined || !isFinite(value)) return "--";
    const size = Math.abs(value);
    if (size >= 1000) return Math.round(value).toLocaleString();
    if (size >= 100) return value.toFixed(0);
    if (size >= 10) return value.toFixed(1);
    if (size >= 1) return value.toFixed(2);
    if (size === 0) return "0";
    return value.toPrecision(3);
  }

  function clockTime(seconds) {
    const when = new Date(seconds * 1000);
    return String(when.getHours()).padStart(2, "0") + ":" +
           String(when.getMinutes()).padStart(2, "0");
  }

  /* An age in seconds as English: "4 minutes", "15 hours", "2 days". Used only
     by the empty state below, where the number is an accusation ("nothing has
     collected a sample for 15 hours") and so has to be readable at a glance.
     Rounded down deliberately: saying "15 hours" when it is 15h 50m understates
     the gap, and an empty state should never overstate a problem. */
  function ago(seconds) {
    if (seconds < 90) return Math.max(0, Math.round(seconds)) + " seconds";
    if (seconds < 5400) return Math.floor(seconds / 60) + " minutes";
    if (seconds < 172800) return Math.floor(seconds / 3600) + " hours";
    return Math.floor(seconds / 86400) + " days";
  }

  /* -------------------------------------------------------------------------
     WHY A CHART IS EMPTY -- one sentence, and it must be the true one.

     Three different situations produce a chart with no line, and the first
     version of this file printed the same words for all three. That is how a
     dashboard lies: "no history for load_per_core yet" was shown while the
     database held 109 samples of load_per_core, none of them newer than the
     hour the chart was asking for. The reader goes looking for a broken store,
     when what is actually broken is that nothing is collecting.

       1. the request failed, or the metric has never been sampled at all
       2. the metric HAS history, but none inside this chart's window --
          i.e. collection has stopped, and the message says when it stopped
       3. exactly one sample exists, which is a point and not yet a line
     ------------------------------------------------------------------------- */
  function emptyReason(payload, metric, seconds) {
    if (!payload || !payload.newest_ts) {
      return "no history for " + metric + " yet";
    }
    const gap = (Date.now() / 1000) - payload.newest_ts;
    if (!payload.points.length) {
      return "nothing collected for " + ago(gap) + " -- newest sample at " +
             clockTime(payload.newest_ts) + ", chart shows the last " +
             ago(seconds) + ". Is the collector running?";
    }
    return "only one sample so far -- a line needs two";
  }

  /* -------------------------------------------------------------------------
     NICE AXIS BOUNDS.

     Using the raw minimum and maximum makes a chart whose axis reads
     "37.428571" and whose line touches both edges. This expands the range to
     round numbers and leaves a margin, so the shape is readable and the labels
     are numbers a human would write.

     THE FLAT-SERIES CASE IS THE ONE THAT MATTERS. Half the metrics in this
     project sit at a constant (swap at 0, zombies at 0). min === max makes the
     height zero and every point lands on the same pixel row -- or worse, on a
     division by zero. So a flat series is given an artificial range around its
     value and drawn as the straight line it is.
     ------------------------------------------------------------------------- */
  function bounds(values) {
    let low = Math.min.apply(null, values);
    let high = Math.max.apply(null, values);

    if (!isFinite(low) || !isFinite(high)) return { low: 0, high: 1 };

    /* A metric that cannot go below zero must not get an axis that does.
       Percentages, counts, rates and byte totals are all non-negative here, and
       an axis reading "-1" under a count of failed units is not a cosmetic
       problem -- it is the chart asserting something impossible. */
    const floorAtZero = Math.min.apply(null, values) >= 0;

    if (low === high) {
      /* The flat series, and this is the case that produced the bug: half the
         metrics in this project sit at a constant (swap at 0, zombies at 0,
         failed units at 0). A zero-height range divides by zero, so a padded
         one is invented -- but padding zero symmetrically gives -1..1, which is
         how a count that has never been anything but zero ended up with a
         negative axis. */
      const pad = Math.abs(low) > 0 ? Math.abs(low) * 0.5 : 1;
      const padded = { low: low - pad, high: high + pad };
      if (padded.low < 0 && floorAtZero) padded.low = 0;
      return padded;
    }

    const span = high - low;
    low -= span * 0.12;
    high += span * 0.12;

    if (low < 0 && floorAtZero) low = 0;
    return { low: low, high: high };
  }

  /* -------------------------------------------------------------------------
     line(element, points, options)

     points   [{ts, value}, ...] oldest first
     options  {band: {mean, stddev}}  draws the baseline and +/- 1 sigma, which
              is what makes an anomaly visible AS an anomaly rather than just a
              wiggle: the eye can see the line leave the band.
     ------------------------------------------------------------------------- */
  function line(element, points, options) {
    options = options || {};
    element.innerHTML = "";

    const usable = (points || []).filter(function (p) {
      return p && p.value !== null && p.value !== undefined && isFinite(p.value);
    });

    if (usable.length < 2) {
      element.outerHTML = '<div class="chart-empty">not enough history yet' +
        (usable.length ? " (" + usable.length + " reading)" : "") + "</div>";
      return;
    }

    /* The viewBox is a fixed coordinate space and the SVG is sized by CSS, so
       the chart scales to its container without any of this arithmetic having
       to know the pixel width. preserveAspectRatio="none" lets it stretch. */
    const W = 600, H = 150;
    const padL = 44, padR = 8, padT = 10, padB = 20;
    const plotW = W - padL - padR;
    const plotH = H - padT - padB;

    element.setAttribute("viewBox", "0 0 " + W + " " + H);
    element.setAttribute("preserveAspectRatio", "none");

    const values = usable.map(function (p) { return p.value; });
    let range = bounds(values);

    /* If a baseline band is supplied it has to fit inside the axis, or the band
       is drawn off the top of the chart and the anomaly looks unremarkable. */
    if (options.band && isFinite(options.band.mean)) {
      const spread = options.band.stddev || 0;
      range.low = Math.min(range.low, options.band.mean - spread * 1.5);
      range.high = Math.max(range.high, options.band.mean + spread * 1.5);
    }

    const firstTs = usable[0].ts;
    const lastTs = usable[usable.length - 1].ts;
    const spanTs = Math.max(1, lastTs - firstTs);

    function x(ts) { return padL + ((ts - firstTs) / spanTs) * plotW; }
    function y(value) {
      const height = range.high - range.low || 1;
      return padT + plotH - ((value - range.low) / height) * plotH;
    }

    /* --- horizontal grid and the value axis ------------------------------ */
    for (let i = 0; i <= 3; i++) {
      const value = range.low + (range.high - range.low) * (i / 3);
      const yy = y(value);
      element.appendChild(make("line", {
        class: "grid-line", x1: padL, x2: W - padR, y1: yy, y2: yy,
      }));
      const label = make("text", {
        class: "axis-label", x: padL - 6, y: yy + 3, "text-anchor": "end",
      });
      label.textContent = pretty(value);
      element.appendChild(label);
    }

    /* --- the baseline band, drawn UNDER the line ------------------------- */
    if (options.band && isFinite(options.band.mean)) {
      const spread = options.band.stddev || 0;
      if (spread > 0) {
        const top = y(options.band.mean + spread);
        const bottom = y(options.band.mean - spread);
        element.appendChild(make("rect", {
          class: "band", x: padL, y: Math.min(top, bottom),
          width: plotW, height: Math.abs(bottom - top),
        }));
      }
      const meanY = y(options.band.mean);
      element.appendChild(make("line", {
        class: "mean", x1: padL, x2: W - padR, y1: meanY, y2: meanY,
      }));
    }

    /* --- the series itself ----------------------------------------------- */
    let path = "";
    usable.forEach(function (point, index) {
      path += (index === 0 ? "M" : "L") + x(point.ts).toFixed(1) + " " + y(point.value).toFixed(1);
    });

    element.appendChild(make("path", {
      class: "area",
      d: path + "L" + x(lastTs).toFixed(1) + " " + (padT + plotH) +
         "L" + x(firstTs).toFixed(1) + " " + (padT + plotH) + "Z",
    }));
    element.appendChild(make("path", { class: "line", d: path }));

    /* The newest reading gets a dot, because "where are we now" is the single
       thing a person looks for first on a time series. */
    const last = usable[usable.length - 1];
    element.appendChild(make("circle", {
      class: "dot", cx: x(last.ts), cy: y(last.value), r: 3,
    }));

    /* --- time axis: first and last only ---------------------------------- */
    const startLabel = make("text", { class: "axis-label", x: padL, y: H - 6 });
    startLabel.textContent = clockTime(firstTs);
    element.appendChild(startLabel);

    const endLabel = make("text", {
      class: "axis-label", x: W - padR, y: H - 6, "text-anchor": "end",
    });
    endLabel.textContent = clockTime(lastTs);
    element.appendChild(endLabel);

    /* A <title> makes the whole chart hoverable with a native tooltip. No
       mousemove handler, no positioning maths, no library -- the browser draws
       it, and it works on a keyboard too. */
    const title = make("title", {});
    title.textContent = usable.length + " readings, " +
      pretty(Math.min.apply(null, values)) + " to " + pretty(Math.max.apply(null, values)) +
      ", latest " + pretty(last.value);
    element.appendChild(title);
  }

  /* -------------------------------------------------------------------------
     spark(element, points) -- a tiny trend line with no axes, for a stat card.
     ------------------------------------------------------------------------- */
  function spark(element, points) {
    element.innerHTML = "";
    const usable = (points || []).filter(function (p) {
      return p && p.value !== null && isFinite(p.value);
    });
    if (usable.length < 2) return;

    const W = 200, H = 34, pad = 3;
    element.setAttribute("viewBox", "0 0 " + W + " " + H);
    element.setAttribute("preserveAspectRatio", "none");

    const values = usable.map(function (p) { return p.value; });
    const range = bounds(values);
    const firstTs = usable[0].ts;
    const spanTs = Math.max(1, usable[usable.length - 1].ts - firstTs);

    let path = "";
    usable.forEach(function (point, index) {
      const px = ((point.ts - firstTs) / spanTs) * W;
      const py = pad + (H - pad * 2) -
        ((point.value - range.low) / (range.high - range.low || 1)) * (H - pad * 2);
      path += (index === 0 ? "M" : "L") + px.toFixed(1) + " " + py.toFixed(1);
    });

    element.appendChild(make("path", { class: "area", d: path + "L" + W + " " + H + "L0 " + H + "Z" }));
    element.appendChild(make("path", { class: "line", d: path }));
  }

  /* -------------------------------------------------------------------------
     load(metric, seconds) -- fetch one series from the API.

     Returns null rather than throwing on failure, because a chart that cannot
     load must leave the rest of the page working. Section 49 of the brief: the
     dashboard has to show something meaningful when a part of it fails.
     ------------------------------------------------------------------------- */
  async function load(metric, seconds) {
    try {
      const response = await fetch("/api/series/" + encodeURIComponent(metric) +
                                   "?seconds=" + (seconds || 3600));
      if (!response.ok) return null;
      const payload = await response.json();
      return payload.status === "ok" ? payload : null;
    } catch (error) {
      return null;
    }
  }

  /* Draw every <svg data-metric="..."> on the page. One call sets up a whole
     page of charts, so a template only has to declare where they go. */
  async function drawAll(root) {
    const targets = (root || document).querySelectorAll("svg[data-metric]");
    for (const element of targets) {
      const window_seconds = parseInt(element.dataset.seconds || "3600", 10);
      const payload = await load(element.dataset.metric, window_seconds);
      if (!payload || payload.points.length < 2) {
        const empty = document.createElement("div");
        empty.className = "chart-empty";
        empty.textContent = emptyReason(payload, element.dataset.metric, window_seconds);
        element.replaceWith(empty);
        continue;
      }
      const options = {};
      if (element.dataset.mean) {
        options.band = {
          mean: parseFloat(element.dataset.mean),
          stddev: parseFloat(element.dataset.stddev || "0"),
        };
      }
      if (element.classList.contains("spark")) {
        spark(element, payload.points);
      } else {
        line(element, payload.points, options);
      }
    }
  }

  global.GuardianCharts = { line: line, spark: spark, load: load, drawAll: drawAll, pretty: pretty };
})(window);
