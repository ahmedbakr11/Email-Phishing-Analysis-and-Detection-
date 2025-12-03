import { useCallback, useState } from "react";
import api from "../../../api/axios.js";

const usePhishingAnalyzer = () => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [collapseKey, setCollapseKey] = useState(0);
  const uploadEmail = useCallback(async (file) => {
    const form = new FormData();
    form.append("eml", file);
    const { data } = await api.post("/tools/Phishing-email/eml-scan", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
  }, []);

  const handleSelectFile = useCallback((file, errMsg) => {
    setSelectedFile(file);
    setReport(null);
    setError(errMsg || null);
    setCollapseKey((k) => k + 1);
  }, []);

  const handleUpload = useCallback(async () => {
    if (!selectedFile) {
      setError("Please choose a .eml file to scan.");
      return;
    }
    setIsLoading(true);
    setError(null);
    try {
      const data = await uploadEmail(selectedFile);
      setReport(data);
      setCollapseKey((k) => k + 1);
    } catch (err) {
      const msg =
        err?.response?.data?.detail ||
        err?.response?.data?.error ||
        err?.message ||
        "Upload failed. Please try again.";
      setError(msg);
    } finally {
      setIsLoading(false);
    }
  }, [selectedFile, uploadEmail]);

  return {
    selectedFile,
    report,
    error,
    isLoading,
    collapseKey,
    handleSelectFile,
    handleUpload,
  };
};

export default usePhishingAnalyzer;
