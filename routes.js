// Add this route (preferably protected with your omni-secret)
app.get('/routes', (req, res) => {
  const routes = [];
  
  // This lists all registered routes
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      const methods = Object.keys(middleware.route.methods).join(',').toUpperCase();
      routes.push({
        method: methods,
        path: middleware.route.path,
        // You can add expected body structure manually if you want
      });
    }
  });

  res.json({
    success: true,
    endpoints: routes,
    message: "Current routes exposed"
  });
});