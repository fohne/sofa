Highcharts.chart('container', {
  chart: {
    type: 'line',
    zoomType:'x'
  },
  title: {
    text: 'Node Connection View in Distributed System'
  },
  subtitle: {
    text: 'Source: OpenSplice'
  },
  xAxis: {
    
  },
  yAxis: {
    // categories: ['A', 'B'],
    title: {
      text: 'Nodes'
    }
  },
  plotOptions: {
    line: {
      dataLabels: {
        enabled: true
      },
      findNearestPointBy: 'xy',
      enableMouseTracking: true,
      boostThreshold:1,
      turboThreshold: 0,
      cropThreshold: 50000
    }
  },
  series:sofa_traces_connect

});
