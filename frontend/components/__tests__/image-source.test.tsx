import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ImageSource } from "@/components/ImageSource";

const listImages = vi.fn();
const uploadImage = vi.fn();

vi.mock("@/lib/api", () => ({
  listImages: () => listImages(),
  uploadImage: (file: File) => uploadImage(file),
}));

const IMAGES = [
  { reference: "alpine:3.20", image_id: "sha1", size: "8MB", created: "1d" },
];

function setup() {
  const onChange = vi.fn();

  render(
    <ImageSource
      value={{ target: "python:3.8", repoId: "python" }}
      onChange={onChange}
    />,
  );

  return onChange;
}

/** Drop a file on the hidden input the upload tab clicks through to. */
function upload(file: File) {
  const input = document.querySelector<HTMLInputElement>("#tarball")!;

  fireEvent.change(input, { target: { files: [file] } });
}

beforeEach(() => {
  listImages.mockReset();
  uploadImage.mockReset();
});

describe("ImageSource", () => {
  it("hides the tabs entirely when there is no daemon", async () => {
    // Registry mode 404s the endpoint. Rendering a picker that cannot work is
    // worse than not offering one.
    listImages.mockRejectedValue(new Error("Not found."));

    setup();

    await waitFor(() =>
      expect(screen.queryByRole("tablist")).not.toBeInTheDocument(),
    );

    expect(screen.getByPlaceholderText("python:3.8")).toBeInTheDocument();
  });

  it("selects an image from the daemon", async () => {
    listImages.mockResolvedValue(IMAGES);

    const onChange = setup();

    fireEvent.click(await screen.findByRole("tab", { name: "My images" }));
    fireEvent.click(await screen.findByText("alpine:3.20"));

    expect(onChange).toHaveBeenLastCalledWith({
      target: "alpine:3.20",
      repoId: "alpine",
    });
  });

  it("clears the previous target when switching away from Registry", async () => {
    // Otherwise clicking "My images" and scanning without picking anything
    // would silently scan whatever the text box still held.
    listImages.mockResolvedValue(IMAGES);

    const onChange = setup();

    fireEvent.click(await screen.findByRole("tab", { name: "My images" }));

    expect(onChange).toHaveBeenCalledWith({ target: "", repoId: "" });
  });

  it("hands the uploaded tar's target back", async () => {
    listImages.mockResolvedValue(IMAGES);
    uploadImage.mockResolvedValue({
      target: "upload://abc123",
      repo_id: "alpine",
    });

    const onChange = setup();

    fireEvent.click(await screen.findByRole("tab", { name: "Upload" }));

    upload(new File(["tar"], "alpine.tar", { type: "application/x-tar" }));

    await waitFor(() =>
      expect(onChange).toHaveBeenLastCalledWith({
        target: "upload://abc123",
        repoId: "alpine",
      }),
    );
  });

  it("shows why an upload was refused", async () => {
    listImages.mockResolvedValue(IMAGES);
    uploadImage.mockRejectedValue(new Error("Upload exceeds 2048MB"));

    setup();

    fireEvent.click(await screen.findByRole("tab", { name: "Upload" }));

    upload(new File(["tar"], "big.tar"));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Upload exceeds 2048MB",
    );
  });
});
