import cv2

for idx in [0, 1]:
    print(f"Testing camera at index {idx}...")
    cap = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
    if cap.isOpened():
        ret, frame = cap.read()
        if ret:
            print(f"Camera at index {idx} is working.")
            cv2.imshow(f"Camera {idx}", frame)
            cv2.waitKey(0)
            cv2.destroyAllWindows()
        else:
            print(f"Camera at index {idx} failed to capture a frame.")
        cap.release()
    else:
        print(f"Failed to open camera at index {idx}.")
