class MLKCase24_CustomAutoCloseableLeak {
    static class LocalRes implements AutoCloseable {
        @Override
        public void close() {
            // no-op
        }
    }

    public void run() {
        LocalRes res = new LocalRes();
        System.out.println(res);
    }
}
