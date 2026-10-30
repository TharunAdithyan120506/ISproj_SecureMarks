import { StrictMode, Suspense, lazy } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./auth";
import { Layout } from "./Layout";
import { Spinner } from "./ui";
import Home from "./pages/Home";
import "./styles.css";

const Publish = lazy(() => import("./pages/Publish"));
const MyMarks = lazy(() => import("./pages/MyMarks"));
const Verify = lazy(() => import("./pages/Verify"));
const Keys = lazy(() => import("./pages/Keys"));
const TextLab = lazy(() => import("./pages/TextLab"));
const ImageLab = lazy(() => import("./pages/ImageLab"));
const HashLab = lazy(() => import("./pages/HashLab"));
const SignLab = lazy(() => import("./pages/SignLab"));
const KexLab = lazy(() => import("./pages/KexLab"));
const Attacks = lazy(() => import("./pages/Attacks"));
const Traffic = lazy(() => import("./pages/Traffic"));
const Report = lazy(() => import("./pages/Report"));
const Benchmarks = lazy(() => import("./pages/Benchmarks"));

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5000 } } });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <AuthProvider>
        <BrowserRouter>
          <Layout>
            <Suspense fallback={<Spinner label="Loading" />}>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/publish" element={<Publish />} />
                <Route path="/marks" element={<MyMarks />} />
                <Route path="/verify" element={<Verify />} />
                <Route path="/keys" element={<Keys />} />
                <Route path="/lab/text" element={<TextLab />} />
                <Route path="/lab/image" element={<ImageLab />} />
                <Route path="/lab/hash" element={<HashLab />} />
                <Route path="/lab/signatures" element={<SignLab />} />
                <Route path="/lab/kex" element={<KexLab />} />
                <Route path="/attacks" element={<Attacks />} />
                <Route path="/traffic" element={<Traffic />} />
                <Route path="/report" element={<Report />} />
                <Route path="/benchmarks" element={<Benchmarks />} />
                <Route path="*" element={<Home />} />
              </Routes>
            </Suspense>
          </Layout>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
);
