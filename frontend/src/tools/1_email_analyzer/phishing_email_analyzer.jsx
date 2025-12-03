import React, { useMemo, useState } from "react";
import Header from "../../components/Header.jsx";
import "../../styles/phishing-email-analyzer.css";
import CollapsiblePane from "./components/CollapsiblePane";
import UploadCard from "./components/UploadCard";
import RiskBanner from "./components/RiskBanner";
import RawReportViewer from "./components/RawReportViewer";
import usePhishingAnalyzer from "./hooks/usePhishingAnalyzer";

const JsonSection = ({ title, tone = "info", hint, data, defaultOpen = false }) => (
  <CollapsiblePane title={title} tone={tone} hint={hint} defaultOpen={defaultOpen}>
    {data ? (
      <div className="phish-raw-pane" style={{ maxHeight: 340 }}>
        <pre className="phish-raw">{JSON.stringify(data, null, 2)}</pre>
      </div>
    ) : (
      <div className="phish-empty">No data returned for this section.</div>
    )}
  </CollapsiblePane>
);

function ToolPhishing() {
  const [rawSearch, setRawSearch] = useState("");
  const {
    selectedFile,
    report,
    error,
    isLoading,
    collapseKey,
    handleSelectFile,
    handleUpload,
  } = usePhishingAnalyzer();

  const rawData = report?.raw_report || {};
  const detectionData = rawData?.detection || {};

  const summary = useMemo(
    () =>
      report
        ? {
            sender: report.sender,
            subject: report.subject,
            status: report.status,
            score: report.score,
            links: report.links,
            attachments: report.attachments,
          }
        : null,
    [report]
  );

  const detectionSections = useMemo(
    () =>
      Object.entries(detectionData).map(([key, value]) => ({
        key,
        title: key,
        tone: "warning",
        hint: `Detection results for ${key}`,
        data: value,
      })),
    [detectionData]
  );

  const extractionSection = useMemo(() => {
    if (!rawData?.extraction) return null;
    return {
      key: "extraction",
      title: "Extraction",
      tone: "info",
      hint: "Artifacts extracted from the email.",
      data: rawData.extraction,
      defaultOpen: true,
    };
  }, [rawData]);

  const scanSections = useMemo(() => {
    const blocks = [];
    if (extractionSection) blocks.push(extractionSection);
    blocks.push(...detectionSections);
    return blocks;
  }, [detectionSections, extractionSection]);

  const hasContent = (value) => {
    if (!value) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === "object") return Object.keys(value).length > 0;
    return true;
  };

  const visibleSections = scanSections.filter((section) => hasContent(section.data));

  return (
    <>
      <Header />
      <style>{`
        .phish-page, .phish-page * {
          color: #fff !important;
        }
      `}</style>
      <main className="tool-page__content phish-page">
        <UploadCard
          selectedFile={selectedFile}
          onSelectFile={handleSelectFile}
          onUpload={handleUpload}
          isLoading={isLoading}
          error={error}
          onReset={() => handleSelectFile(null, null)}
        />

        {report && (
          <>
            <section className="phish-card phish-card--result">
              <div className="phish-card__header">
                <h2 className="phish-card__title">Risk Assessment</h2>
              </div>
              <RiskBanner report={report} />
            </section>

            {summary && (
              <section className="phish-card phish-card--result">
                <div className="phish-card__header">
                  <h2 className="phish-card__title">Summary</h2>
                </div>
                <div className="phish-raw-pane" style={{ maxHeight: 340 }}>
                  <pre className="phish-raw">{JSON.stringify(summary, null, 2)}</pre>
                </div>
              </section>
            )}

            <section className="phish-card phish-card--result">
              <div className="phish-card__header">
                <h2 className="phish-card__title">Scan Results</h2>
              </div>

              <div className="phish-section">
                <div className="phish-findings">
                  {visibleSections.length === 0 && (
                    <div className="phish-empty">No results returned from the analyzer.</div>
                  )}
                  {visibleSections.map((section) => (
                    <JsonSection
                      key={`${section.title}-${collapseKey}`}
                      title={section.title}
                      tone={section.tone}
                      hint={section.hint}
                      data={section.data}
                      defaultOpen={section.defaultOpen}
                    />
                  ))}
                </div>
              </div>
            </section>

            {report.raw_report && (
              <section className="phish-card phish-card--result">
                <div className="phish-card__header">
                  <h2 className="phish-card__title">Raw report JSON</h2>
                </div>
                <CollapsiblePane title="Raw report JSON" tone="info">
                  <RawReportViewer data={report.raw_report} search={rawSearch} onSearch={setRawSearch} />
                </CollapsiblePane>
              </section>
            )}
          </>
        )}
      </main>
    </>
  );
}

export default ToolPhishing;
