import React, { useRef, useState } from "react";
import { ICONS } from "../utils/constants";
import { formatBytes } from "../utils/phishingUtils";
import Loader from "./Loader";

const UploadCard = ({ selectedFile, onSelectFile, onUpload, isLoading, error, onReset }) => {
  const [isDragging, setIsDragging] = useState(false);
  const inputRef = useRef(null);

  const onChange = (event) => {
    const file = event.target.files?.[0];
    if (file && !file.name.toLowerCase().endsWith(".eml")) {
      onSelectFile?.(null, "Only .eml files are supported.");
      return;
    }
    onSelectFile?.(file || null, null);
    event.target.value = "";
  };

  const onDrop = (event) => {
    event.preventDefault();
    setIsDragging(false);
    const [file] = event.dataTransfer?.files || [];
    if (file && !file.name.toLowerCase().endsWith(".eml")) {
      onSelectFile?.(null, "Only .eml files are supported.");
      return;
    }
    onSelectFile?.(file || null, null);
  };

  const onDrag = (event) => {
    event.preventDefault();
    setIsDragging(event.type === "dragover");
  };

  const handleUpload = () => onUpload?.();

  return (

      <div className="phish-upload-card">
        <div className="phish-upload-head">
          <div>
            <h1 className="tool-page__title">Phishing Email Analyzer</h1>
        </div>
        </div>
        <div
          className={`phish-dropzone ${isDragging ? "is-dragging" : ""}`}
          onDragOver={onDrag}
          onDragLeave={onDrag}
          onDrop={onDrop}
          role="button"
          tabIndex={0}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              inputRef.current?.click();
            }
          }}
          title="Drop your .eml file here or click to browse"
          onClick={() => inputRef.current?.click()}
        >
          <div className="drop-copy">
            <p className="drop-title">Drop email file here</p>
          </div>
          <div className="drop-cta">Browse file</div>
          <input
            ref={inputRef}
            id="eml-file-input"
            type="file"
            accept=".eml"
            onChange={onChange}
            className="visually-hidden"
          />
        </div>

        {selectedFile && (
          <div className="phish-file-preview">
            <div className="file-chip">
              <div className="file-meta">
                <div className="file-name break-all">{selectedFile.name}</div>

              </div>
            </div>
            <div className="file-actions">
              <button
                type="button"
                className="btn btn-secondary phish-secondary-btn"
                onClick={onReset}
                disabled={isLoading}
              >
                Clear
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleUpload}
                disabled={isLoading}
              >
                {isLoading ? "Scanning..." : "Upload & Scan"}
              </button>
            </div>
          </div>
        )}

        <div className="phish-upload-footer">
         {isLoading && <Loader />}
          {error && (
            <div className="form-error phish-error" role="alert">
              {error}
            </div>
          )}
        </div>
      </div>
  );
};

export default UploadCard;
