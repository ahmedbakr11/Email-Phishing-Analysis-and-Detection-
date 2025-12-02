import React, { useMemo, useState } from "react";
import Header from "../../components/header.jsx";
import "../../styles/phishing-email-analyzer.css";
import CollapsiblePane from "./components/CollapsiblePane";
import UploadCard from "./components/UploadCard";
import RiskBanner from "./components/RiskBanner";
import RawReportViewer from "./components/RawReportViewer";
import usePhishingAnalyzer from "./hooks/usePhishingAnalyzer";

const EXTRA_FLAG_LABELS = {
  anchor_redirect: "Anchor Redirect Mismatch",
  typosquatting: "Typosquatting",
  display_spoof: "Display Name Spoofing",
  header_forgery: "Header Forgery",
  double_extension: "Double Extension Attachments",
  html_forms: "HTML Forms",
  clickable_images: "Clickable Images",
  social_engineering: "Social Engineering Language",
  brand_impersonation_variants: "Brand Impersonation Variants",
  risky_tlds: "Risky TLD Links",
};

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
  const sections = useMemo(() => {
    const detectionData = rawData?.detection || {};
    const extraFlags = detectionData.extra_flags || {};
    const statusValue = report?.raw_report?.detection?.score?.verdict || report?.status || "review";
    const summary = report
      ? {
          sender: report.sender,
          subject: report.subject,
          status: (statusValue || "").toString().toLowerCase(),
          score: report.score,
          links: report.links ?? report?.raw_report?.extraction?.raw_links?.length ?? 0,
          attachments: report.attachments ?? report?.raw_report?.extraction?.attachments?.length ?? 0,
        }
      : null;
    const detectionBlocks = Object.entries(detectionData)
      .filter(([key]) => key !== "extra_flags" && key !== "score")
      .map(([key, value]) => ({
        key,
        title: key,
        tone: "warning",
        hint: `Detection results for ${key}`,
        data: value,
      }));
    const extraFlagBlocks = Object.entries(EXTRA_FLAG_LABELS).map(([flagKey, display]) => ({
      key: `extra-${flagKey}`,
      title: display || flagKey,
      tone: "info",
      hint: `Extra flag details for ${display || flagKey}`,
      data: extraFlags[flagKey],
      defaultOpen: true,
    }));
    return [
      {
        key: "summary",
        title: "Summary",
        tone: "safe",
        hint: "Top-level summary fields returned by the analyzer.",
        data: summary,
        defaultOpen: true,
      },
      ...detectionBlocks,
      ...extraFlagBlocks,
    ];
  }, [rawData, report]);

  const hasContent = (value) => {
    if (!value) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === "object") return Object.keys(value).length > 0;
    return true;
  };

  const visibleSections = sections.filter((section) => hasContent(section.data));

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

              {report.raw_report && (
                <div className="phish-section">
                  <CollapsiblePane title="Raw report JSON" tone="info">
                    <RawReportViewer
                      data={report.raw_report}
                      search={rawSearch}
                      onSearch={setRawSearch}
                    />
                  </CollapsiblePane>
                </div>
              )}
            </section>
          </>
        )}
      </main>
    </>
  );
}

export default ToolPhishing;
