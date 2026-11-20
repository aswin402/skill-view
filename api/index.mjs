import app from "./_handler.mjs";

export default {
  fetch(request) {
    return app.fetch(request);
  },
};
