import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

public class SignOffServiceTest {

    @Mock
    private EventService eventService;

    @Mock
    private ReportService reportService;

    @InjectMocks
    private SignOffService signOffService;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testSignOffForFirstLevel() throws SignOffException {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn(Constants.FIRST_LEVEL_SIGN_OFF);
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");
        when(signOff.getDatasetId()).thenReturn("datasetId");
        when(signOff.getDataDNSId()).thenReturn("dataDNSId");

        Report report = mock(Report.class);
        when(reportService.getReport("reportId")).thenReturn(report);
        when(report.getLevelOneSignOff()).thenReturn(List.of(kerberos));

        when(eventService.isSignedOffForFirstLevel(any(), any())).thenReturn(true);
        when(eventService.getFirstLevelSignedOffEvent(any(), any(), any())).thenReturn(new Event());

        boolean result = signOffService.signOff(signOff, kerberos);

        assertTrue(result);
        verify(eventService).insertEvent(any(Event.class));
    }

    @Test
    public void testSignOffForSecondLevel() throws SignOffException {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn(Constants.SECOND_LEVEL_SIGN_OFF);
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");
        when(signOff.getDatasetId()).thenReturn("datasetId");
        when(signOff.getDataDNSId()).thenReturn("dataDNSId");

        Report report = mock(Report.class);
        when(reportService.getReport("reportId")).thenReturn(report);
        when(report.getLevelOneSignOff()).thenReturn(List.of(kerberos));

        when(eventService.isSignedOffForFirstLevel(any(), any())).thenReturn(true);
        when(eventService.isSignedOffForSecondLevel(any(), any())).thenReturn(false);
        when(eventService.getSecondLevelSignedOffEvent(any(), any(), any())).thenReturn(new Event());

        boolean result = signOffService.signOff(signOff, kerberos);

        assertTrue(result);
        verify(eventService).insertEvent(any(Event.class));
    }

    @Test
    public void testUnauthorizedSignOff() {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn(Constants.SECOND_LEVEL_SIGN_OFF);
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");

        Report report = mock(Report.class);
        when(reportService.getReport("reportId")).thenReturn(report);
        when(report.getLevelOneSignOff()).thenReturn(List.of());

        when(eventService.isSignedOffForFirstLevel(any(), any())).thenReturn(false);

        assertThrows(UnauthorizedSignoffException.class, () -> {
            signOffService.signOff(signOff, kerberos);
        });
    }

    @Test
    public void testDatasetIdMismatch() {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn(Constants.SECOND_LEVEL_SIGN_OFF);
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");
        when(signOff.getDatasetId()).thenReturn("datasetId");
        when(signOff.getDataDNSId()).thenReturn("dataDNSId");

        Report report = mock(Report.class);
        when(reportService.getReport("reportId")).thenReturn(report);
        when(report.getLevelOneSignOff()).thenReturn(List.of(kerberos));

        when(eventService.isSignedOffForFirstLevel(any(), any())).thenReturn(true);
        when(signOff.getDataDNSId()).thenReturn("differentDataDNSId");

        assertThrows(DataSetIdMismatchException.class, () -> {
            signOffService.signOff(signOff, kerberos);
        });
    }

    @Test
    public void testSignOffAlreadyCompleted() {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn(Constants.SECOND_LEVEL_SIGN_OFF);
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");
        when(signOff.getDatasetId()).thenReturn("datasetId");
        when(signOff.getDataDNSId()).thenReturn("dataDNSId");

        Report report = mock(Report.class);
        when(reportService.getReport("reportId")).thenReturn(report);
        when(report.getLevelOneSignOff()).thenReturn(List.of(kerberos));

        when(eventService.isSignedOffForFirstLevel(any(), any())).thenReturn(true);
        when(eventService.isSignedOffForSecondLevel(any(), any())).thenReturn(true);

        assertThrows(SecondLevelSignOffException.class, () -> {
            signOffService.signOff(signOff, kerberos);
        });
    }

    @Test
    public void testUserSigningOffForBothLevels() {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn(Constants.SECOND_LEVEL_SIGN_OFF);
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");
        when(signOff.getDatasetId()).thenReturn("datasetId");
        when(signOff.getDataDNSId()).thenReturn("dataDNSId");

        Report report = mock(Report.class);
        when(reportService.getReport("reportId")).thenReturn(report);
        when(report.getLevelOneSignOff()).thenReturn(List.of(kerberos));

        when(eventService.isSignedOffForFirstLevel(any(), any())).thenReturn(true);
        when(eventService.getFirstLevelSignedOffEvent(any(), any(), any())).thenReturn(new Event());

        Event firstLevelEvent = new Event();
        firstLevelEvent.setCreatedBy(kerberos);

        when(eventService.getFirstLevelSignedOffEvent(any(), any(), any())).thenReturn(firstLevelEvent);

        assertThrows(UnauthorizedSignoffException.class, () -> {
            signOffService.signOff(signOff, kerberos);
        });
    }

    @Test
    public void testInvalidSignOffLevel() {
        SignOff signOff = mock(SignOff.class);
        String kerberos = "user123";

        when(signOff.getSignOffLevel()).thenReturn("INVALID_LEVEL");
        when(signOff.getBusinessDate()).thenReturn(new Timestamp(System.currentTimeMillis()));
        when(signOff.getReportId()).thenReturn("reportId");
        when(signOff.getDatasetId()).thenReturn("datasetId");
        when(signOff.getDataDNSId()).thenReturn("dataDNSId");

        assertThrows(SignOffException.class, () -> {
            signOffService.signOff(signOff, kerberos);
        });
    }
}
